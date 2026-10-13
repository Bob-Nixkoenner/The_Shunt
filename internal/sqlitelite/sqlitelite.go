// Package sqlitelite reads rows of one table from an SQLite database file,
// read-only and without cgo: enough for small lookups such as Firefox's
// profile names. Pages still in the write-ahead log (-wal) are taken into
// account; the file is never written or locked.
package sqlitelite

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"
)

// maxPages bounds every walk: a broken or hostile file must not loop.
const maxPages = 1 << 16

type db struct {
	data     []byte
	pageSize int
	usable   int
	wal      map[uint32][]byte
}

// Rows returns the rows of table as column name -> value (int64, float64,
// string, []byte or nil). Column names come from the CREATE TABLE statement.
func Rows(path, table string) ([]map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) < 100 || !bytes.HasPrefix(data, []byte("SQLite format 3\x00")) {
		return nil, errors.New("not an SQLite database")
	}
	ps := int(binary.BigEndian.Uint16(data[16:]))
	if ps == 1 {
		ps = 65536
	}
	if ps < 512 || ps&(ps-1) != 0 {
		return nil, fmt.Errorf("bad page size %d", ps)
	}
	d := &db{data: data, pageSize: ps, usable: ps - int(data[20])}
	if w, err := os.ReadFile(path + "-wal"); err == nil {
		d.wal = readWAL(w, ps)
	}
	var root int64
	var sql string
	err = d.walk(1, func(rec []any) {
		if len(rec) >= 5 && rec[0] == "table" && rec[1] == table {
			root, _ = rec[3].(int64)
			sql, _ = rec[4].(string)
		}
	})
	if err != nil {
		return nil, err
	}
	if root == 0 {
		return nil, fmt.Errorf("no table %q", table)
	}
	cols := columns(sql)
	var out []map[string]any
	err = d.walk(uint32(root), func(rec []any) {
		row := map[string]any{}
		for i, v := range rec {
			if i < len(cols) {
				row[cols[i]] = v
			}
		}
		out = append(out, row)
	})
	return out, err
}

// readWAL returns the newest committed copy of every page in the log.
func readWAL(w []byte, ps int) map[uint32][]byte {
	if len(w) < 32 || binary.BigEndian.Uint32(w)&^1 != 0x377f0682 || int(binary.BigEndian.Uint32(w[8:])) != ps {
		return nil
	}
	salt1, salt2 := binary.BigEndian.Uint32(w[16:]), binary.BigEndian.Uint32(w[20:])
	pages, pending := map[uint32][]byte{}, map[uint32][]byte{}
	for off := 32; off+24+ps <= len(w); off += 24 + ps {
		h := w[off:]
		if binary.BigEndian.Uint32(h[8:]) != salt1 || binary.BigEndian.Uint32(h[12:]) != salt2 {
			break // frames of an older log generation
		}
		pending[binary.BigEndian.Uint32(h)] = w[off+24 : off+24+ps]
		if binary.BigEndian.Uint32(h[4:]) != 0 { // commit frame
			for k, v := range pending {
				pages[k] = v
			}
			pending = map[uint32][]byte{}
		}
	}
	return pages
}

func (d *db) page(n uint32) ([]byte, error) {
	if p, ok := d.wal[n]; ok {
		return p, nil
	}
	off := int(n-1) * d.pageSize
	if n == 0 || off+d.pageSize > len(d.data) {
		return nil, fmt.Errorf("page %d out of range", n)
	}
	return d.data[off : off+d.pageSize], nil
}

// walk calls fn for every record of the table b-tree rooted at root.
func (d *db) walk(root uint32, fn func([]any)) error {
	stack, seen := []uint32{root}, 0
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen++; seen > maxPages {
			return errors.New("too many pages")
		}
		p, err := d.page(n)
		if err != nil {
			return err
		}
		h := 0
		if n == 1 {
			h = 100 // page 1 starts with the file header
		}
		if len(p) < h+12 {
			return errors.New("short page")
		}
		kind, cells := p[h], int(binary.BigEndian.Uint16(p[h+3:]))
		hdr := 8
		if kind == 0x05 {
			hdr = 12
		}
		ptrs := h + hdr
		if ptrs+2*cells > len(p) {
			return errors.New("bad cell count")
		}
		switch kind {
		case 0x05: // interior table page: children in order, then the right-most
			stack = append(stack, binary.BigEndian.Uint32(p[h+8:]))
			for i := cells - 1; i >= 0; i-- {
				c := int(binary.BigEndian.Uint16(p[ptrs+2*i:]))
				if c+4 > len(p) {
					return errors.New("bad cell")
				}
				stack = append(stack, binary.BigEndian.Uint32(p[c:]))
			}
		case 0x0d: // leaf table page
			for i := 0; i < cells; i++ {
				c := int(binary.BigEndian.Uint16(p[ptrs+2*i:]))
				payload, err := d.cell(p, c)
				if err != nil {
					return err
				}
				rec, err := record(payload)
				if err != nil {
					return err
				}
				fn(rec)
			}
		default:
			return fmt.Errorf("page %d: not a table page (%#x)", n, kind)
		}
	}
	return nil
}

// cell returns the full payload of a leaf table cell at offset c.
func (d *db) cell(p []byte, c int) ([]byte, error) {
	if c >= len(p) {
		return nil, errors.New("bad cell offset")
	}
	size, n := varint(p[c:])
	c += n
	_, m := varint(p[c:]) // rowid
	c += m
	if n == 0 || m == 0 || size > 1<<24 {
		return nil, errors.New("bad payload size")
	}
	total := int(size)
	u := d.usable
	x := u - 35
	local := total
	if total > x {
		m := (u-12)*32/255 - 23
		k := m + (total-m)%(u-4)
		local = m
		if k <= x {
			local = k
		}
	}
	if c+local > len(p) {
		return nil, errors.New("bad payload")
	}
	out := append([]byte(nil), p[c:c+local]...)
	if local == total {
		return out, nil
	}
	if c+local+4 > len(p) {
		return nil, errors.New("bad overflow pointer")
	}
	next := binary.BigEndian.Uint32(p[c+local:])
	for hops := 0; len(out) < total && next != 0; hops++ {
		if hops > maxPages {
			return nil, errors.New("overflow chain too long")
		}
		op, err := d.page(next)
		if err != nil {
			return nil, err
		}
		next = binary.BigEndian.Uint32(op)
		out = append(out, op[4:min(u, 4+total-len(out))]...)
	}
	if len(out) != total {
		return nil, errors.New("short overflow chain")
	}
	return out, nil
}

// record decodes an SQLite record into values.
func record(b []byte) ([]any, error) {
	hsize, n := varint(b)
	if n == 0 || hsize > uint64(len(b)) || hsize < uint64(n) {
		return nil, errors.New("bad record header")
	}
	var types []int64
	for off := n; off < int(hsize); {
		t, m := varint(b[off:])
		if m == 0 {
			return nil, errors.New("bad serial type")
		}
		types = append(types, int64(t))
		off += m
	}
	body := b[hsize:]
	var out []any
	for _, t := range types {
		var size int
		switch {
		case t == 0, t == 8, t == 9:
		case t >= 1 && t <= 4:
			size = int(t)
		case t == 5:
			size = 6
		case t == 6, t == 7:
			size = 8
		case t >= 12:
			size = int((t - 12) / 2)
		default:
			return nil, fmt.Errorf("serial type %d", t)
		}
		if size > len(body) {
			return nil, errors.New("short record")
		}
		v := body[:size]
		body = body[size:]
		switch {
		case t == 0:
			out = append(out, nil)
		case t == 8:
			out = append(out, int64(0))
		case t == 9:
			out = append(out, int64(1))
		case t <= 6:
			var x int64
			for _, c := range v {
				x = x<<8 | int64(c)
			}
			if shift := 64 - 8*size; shift > 0 { // sign extend
				x = x << shift >> shift
			}
			out = append(out, x)
		case t == 7:
			out = append(out, math.Float64frombits(binary.BigEndian.Uint64(v)))
		case t%2 == 0:
			out = append(out, append([]byte(nil), v...))
		default:
			out = append(out, string(v))
		}
	}
	return out, nil
}

// varint decodes an SQLite varint; n == 0 means truncated.
func varint(b []byte) (uint64, int) {
	var x uint64
	for i := 0; i < 9 && i < len(b); i++ {
		if i == 8 {
			return x<<8 | uint64(b[i]), 9
		}
		x = x<<7 | uint64(b[i]&0x7f)
		if b[i] < 0x80 {
			return x, i + 1
		}
	}
	return 0, 0
}

// columns extracts the column names of a CREATE TABLE statement.
func columns(sql string) []string {
	i, j := strings.Index(sql, "("), strings.LastIndex(sql, ")")
	if i < 0 || j <= i {
		return nil
	}
	var out []string
	depth, start := 0, i+1
	body := sql[:j]
	for k := i + 1; k <= len(body); k++ {
		if k < len(body) {
			switch body[k] {
			case '(':
				depth++
				continue
			case ')':
				depth--
				continue
			case ',':
				if depth > 0 {
					continue
				}
			default:
				continue
			}
		}
		f := strings.Fields(body[start:k])
		start = k + 1
		if len(f) == 0 {
			continue
		}
		switch strings.ToUpper(f[0]) {
		case "PRIMARY", "UNIQUE", "CONSTRAINT", "FOREIGN", "CHECK":
			continue
		}
		out = append(out, strings.Trim(f[0], "\"`[]"))
	}
	return out
}
