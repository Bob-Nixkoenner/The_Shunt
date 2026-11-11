package evidence

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

// A small pcapng (draft-ietf-opsawg-pcapng) writer and reader, pure Go.
// Blocks used: Section Header (0x0A0D0D0A), Interface Description (1) and
// Enhanced Packet (6). Options used: opt_comment (1) on packets, if_name
// (2) and if_tsresol (9) on interfaces, shb_userappl (4) on the section.
// Time stamps are nanoseconds since the epoch (if_tsresol = 9).

const (
	blockSHB = 0x0A0D0D0A
	blockIDB = 1
	blockEPB = 6

	byteOrderMagic = 0x1A2B3C4D

	optEnd     = 0
	optComment = 1
	optIfName  = 2
	optTsresol = 9
	optUserApp = 4

	// Link types.
	LinkEthernet = 1
	LinkRaw      = 101 // raw IPv4/IPv6 (what NFLOG hands over)

	maxBlock = 1 << 20 // the reader refuses bigger blocks
)

// PcapWriter writes one pcapng section (little endian).
type PcapWriter struct {
	w     io.Writer
	n     int64
	ifs   int
	snaps []uint32
}

// NewPcapWriter writes the section header.
func NewPcapWriter(w io.Writer, app string) (*PcapWriter, error) {
	p := &PcapWriter{w: w}
	var body bytes.Buffer
	le := binary.LittleEndian
	_ = binary.Write(&body, le, uint32(byteOrderMagic))
	_ = binary.Write(&body, le, uint16(1)) // major
	_ = binary.Write(&body, le, uint16(0)) // minor
	_ = binary.Write(&body, le, int64(-1)) // section length unknown
	writeOpt(&body, optUserApp, []byte(app))
	writeOpt(&body, optEnd, nil)
	return p, p.block(blockSHB, body.Bytes())
}

func pad4(n int) int { return (4 - n%4) % 4 }

func writeOpt(b *bytes.Buffer, code uint16, v []byte) {
	_ = binary.Write(b, binary.LittleEndian, code)
	_ = binary.Write(b, binary.LittleEndian, uint16(len(v)))
	b.Write(v)
	b.Write(make([]byte, pad4(len(v))))
}

func (p *PcapWriter) block(typ uint32, body []byte) error {
	total := uint32(12 + len(body))
	var b bytes.Buffer
	_ = binary.Write(&b, binary.LittleEndian, typ)
	_ = binary.Write(&b, binary.LittleEndian, total)
	b.Write(body)
	_ = binary.Write(&b, binary.LittleEndian, total)
	n, err := p.w.Write(b.Bytes())
	p.n += int64(n)
	return err
}

// Written is the number of bytes written so far.
func (p *PcapWriter) Written() int64 { return p.n }

// AddInterface writes an Interface Description Block and returns its id.
func (p *PcapWriter) AddInterface(link uint16, snaplen uint32, name string) (int, error) {
	var body bytes.Buffer
	le := binary.LittleEndian
	_ = binary.Write(&body, le, link)
	_ = binary.Write(&body, le, uint16(0))
	_ = binary.Write(&body, le, snaplen)
	if name != "" {
		writeOpt(&body, optIfName, []byte(name))
	}
	writeOpt(&body, optTsresol, []byte{9})
	writeOpt(&body, optEnd, nil)
	if err := p.block(blockIDB, body.Bytes()); err != nil {
		return 0, err
	}
	p.snaps = append(p.snaps, snaplen)
	p.ifs++
	return p.ifs - 1, nil
}

// WritePacket writes an Enhanced Packet Block. data is cut to the
// interface's snaplen; origLen is the length on the wire. comment may be "".
func (p *PcapWriter) WritePacket(ifID int, t time.Time, data []byte, origLen int, comment string) error {
	if ifID < 0 || ifID >= p.ifs {
		return errors.New("pcapng: unknown interface")
	}
	if s := p.snaps[ifID]; s > 0 && uint32(len(data)) > s {
		data = data[:s]
	}
	if origLen < len(data) {
		origLen = len(data)
	}
	var body bytes.Buffer
	le := binary.LittleEndian
	ns := uint64(t.UnixNano())
	_ = binary.Write(&body, le, uint32(ifID))
	_ = binary.Write(&body, le, uint32(ns>>32))
	_ = binary.Write(&body, le, uint32(ns))
	_ = binary.Write(&body, le, uint32(len(data)))
	_ = binary.Write(&body, le, uint32(origLen))
	body.Write(data)
	body.Write(make([]byte, pad4(len(data))))
	if comment != "" {
		writeOpt(&body, optComment, []byte(comment))
		writeOpt(&body, optEnd, nil)
	}
	return p.block(blockEPB, body.Bytes())
}

// Packet is one packet read back.
type Packet struct {
	If      int
	Link    uint16
	Time    time.Time
	Data    []byte
	OrigLen int
	Comment string
	IfName  string
}

// ReadPcap parses a whole pcapng stream (both byte orders). It is strict
// about block sizes and never allocates more than maxBlock per block, so it
// is safe on untrusted input. Unknown blocks are skipped.
func ReadPcap(r io.Reader) ([]Packet, error) {
	var bo binary.ByteOrder
	type ifc struct {
		link uint16
		name string
		unit func(uint64) time.Time
	}
	var ifs []ifc
	var out []Packet
	first := true
	for {
		var hdr [8]byte
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			if err == io.EOF {
				return out, nil
			}
			return out, fmt.Errorf("pcapng: truncated block header: %w", err)
		}
		typ := binary.LittleEndian.Uint32(hdr[:4])
		var total uint32
		if first {
			if typ != blockSHB {
				return nil, errors.New("pcapng: not a pcapng file")
			}
			// byte order comes from the magic inside the block
			var m [4]byte
			if _, err := io.ReadFull(r, m[:]); err != nil {
				return nil, errors.New("pcapng: truncated section header")
			}
			switch binary.LittleEndian.Uint32(m[:]) {
			case byteOrderMagic:
				bo = binary.LittleEndian
			case 0x4D3C2B1A:
				bo = binary.BigEndian
			default:
				return nil, errors.New("pcapng: bad byte-order magic")
			}
			total = bo.Uint32(hdr[4:])
			if total < 28 || total > maxBlock || total%4 != 0 {
				return nil, errors.New("pcapng: bad section header length")
			}
			rest := make([]byte, total-12)
			if _, err := io.ReadFull(r, rest); err != nil {
				return nil, errors.New("pcapng: truncated section header")
			}
			if bo.Uint32(rest[len(rest)-4:]) != total {
				return nil, errors.New("pcapng: section header length mismatch")
			}
			first = false
			continue
		}
		typ = bo.Uint32(hdr[:4])
		total = bo.Uint32(hdr[4:])
		if total < 12 || total > maxBlock || total%4 != 0 {
			return out, fmt.Errorf("pcapng: bad block length %d", total)
		}
		body := make([]byte, total-8)
		if _, err := io.ReadFull(r, body); err != nil {
			return out, fmt.Errorf("pcapng: truncated block: %w", err)
		}
		if bo.Uint32(body[len(body)-4:]) != total {
			return out, errors.New("pcapng: block length mismatch")
		}
		body = body[:len(body)-4]
		switch typ {
		case blockSHB:
			return out, errors.New("pcapng: second section not supported")
		case blockIDB:
			if len(body) < 8 {
				return out, errors.New("pcapng: short interface block")
			}
			c := ifc{link: bo.Uint16(body[0:2])}
			div := uint64(1_000_000) // default resolution: microseconds
			opts, err := parseOpts(bo, body[8:])
			if err != nil {
				return out, err
			}
			for _, o := range opts {
				switch o.code {
				case optIfName:
					c.name = string(o.val)
				case optTsresol:
					if len(o.val) == 1 && o.val[0]&0x80 == 0 && o.val[0] <= 9 {
						div = 1
						for i := byte(0); i < o.val[0]; i++ {
							div *= 10
						}
					}
				}
			}
			d := div
			c.unit = func(v uint64) time.Time {
				return time.Unix(int64(v/d), int64(v%d)*int64(1_000_000_000/d)).UTC()
			}
			ifs = append(ifs, c)
		case blockEPB:
			if len(body) < 20 {
				return out, errors.New("pcapng: short packet block")
			}
			id := int(bo.Uint32(body[0:4]))
			if id >= len(ifs) {
				return out, errors.New("pcapng: packet for unknown interface")
			}
			ts := uint64(bo.Uint32(body[4:8]))<<32 | uint64(bo.Uint32(body[8:12]))
			capLen := int(bo.Uint32(body[12:16]))
			orig := int(bo.Uint32(body[16:20]))
			if capLen < 0 || capLen > len(body)-20 {
				return out, errors.New("pcapng: captured length too large")
			}
			p := Packet{If: id, Link: ifs[id].link, IfName: ifs[id].name, Time: ifs[id].unit(ts), Data: append([]byte(nil), body[20:20+capLen]...), OrigLen: orig}
			optStart := 20 + capLen + pad4(capLen)
			if optStart < len(body) {
				opts, err := parseOpts(bo, body[optStart:])
				if err != nil {
					return out, err
				}
				for _, o := range opts {
					if o.code == optComment {
						p.Comment = string(o.val)
					}
				}
			}
			out = append(out, p)
		}
	}
}

type pcapOpt struct {
	code uint16
	val  []byte
}

func parseOpts(bo binary.ByteOrder, b []byte) ([]pcapOpt, error) {
	var out []pcapOpt
	for len(b) >= 4 {
		code, l := bo.Uint16(b[0:2]), int(bo.Uint16(b[2:4]))
		if code == optEnd {
			return out, nil
		}
		if 4+l > len(b) {
			return out, errors.New("pcapng: option longer than its block")
		}
		out = append(out, pcapOpt{code, b[4 : 4+l]})
		adv := 4 + l + pad4(l)
		if adv > len(b) {
			adv = len(b)
		}
		b = b[adv:]
	}
	return out, nil
}
