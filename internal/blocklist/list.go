// Package blocklist loads DNS blocklists (Pi-hole/AdGuard style) and
// answers "is this name blocked at level X?" for the DNS proxy.
//
// Default sources: RPiList (https://github.com/RPiList/specials) and HaGeZi
// (https://github.com/hagezi/dns-blocklists) – thank you for maintaining
// these lists.
package blocklist

import (
	"bufio"
	"errors"
	"hash/maphash"
	"io"
	"slices"
	"strings"
)

// List is one parsed blocklist. It keeps no names, only a sorted array of
// 64-bit hashes (8 bytes per name instead of about 100 for a map of
// strings; Bob's paranoid setup has 14 million names). The lowest bit of a
// key says whether the name's subdomains are blocked too ("||example.com^")
// or only the name itself (hosts files, plain names). A false hit needs two
// different names with the same 63-bit hash: about 1 in 10^12 per lookup.
type List struct {
	Name string
	// Truncated: the list had more than MaxEntries names; only the first
	// MaxEntries are in it.
	Truncated bool
	keys      []uint64 // sorted, one per name
	// idx[b] is the first position in keys whose top bits are >= b, so a
	// lookup only scans a handful of keys (about 8) instead of a binary
	// search through millions.
	idx   []uint32
	shift uint
}

// seed: one per process, so nobody can build names that collide on purpose
// (hashes never leave the process).
var seed = maphash.MakeSeed()

func hashName(s string) uint64 { return maphash.String(seed, s) &^ 1 }

// Len is the number of entries.
func (l *List) Len() int { return len(l.keys) }

// bucketSize: average number of keys per index slot.
const bucketSize = 8

// build sorts keys, drops duplicates (with subdomains wins, as in the
// lists), trims the array to its length and builds the index.
func build(name string, keys []uint64) *List {
	slices.Sort(keys)
	out := keys[:0]
	for _, k := range keys {
		if n := len(out); n > 0 && out[n-1]&^1 == k&^1 {
			out[n-1] |= k & 1 // sorted: the flagged copy comes last
			continue
		}
		out = append(out, k)
	}
	keys = slices.Clone(out) // drops the growth slack of the parser
	bits := uint(0)
	for (1<<bits)*bucketSize < len(keys) {
		bits++
	}
	l := &List{Name: name, keys: keys, shift: 64 - bits, idx: make([]uint32, (1<<bits)+1)}
	b := 0
	for i, k := range keys {
		for kb := int(l.bucket(k)); b <= kb; b++ {
			l.idx[b] = uint32(i)
		}
	}
	for ; b < len(l.idx); b++ {
		l.idx[b] = uint32(len(keys))
	}
	return l
}

func (l *List) bucket(k uint64) uint64 {
	if l.shift == 64 {
		return 0
	}
	return k >> l.shift
}

// lookup finds base (a hash with the low bit clear): found, and whether
// subdomains are blocked.
func (l *List) lookup(base uint64) (found, sub bool) {
	b := l.bucket(base)
	for _, k := range l.keys[l.idx[b]:l.idx[b+1]] {
		if k&^1 == base {
			return true, k&1 == 1
		}
		if k > base|1 {
			break
		}
	}
	return false, false
}

// MaxLine: longer lines are skipped (a valid name is at most 253 bytes).
const MaxLine = 4096

// MaxEntries caps one list (report L-05): 20 million names are about 160 MB
// in memory (8 bytes each), more than the biggest public lists (about 2
// million). The file limits alone allowed far more: a 256 MiB file of
// one-letter names would be 128 million. A list that reaches the cap keeps
// its first MaxEntries names and is marked Truncated (said loudly).
var MaxEntries = 20_000_000

// ErrEmpty: the file had no usable entry – probably not a blocklist (an
// error page, a moved file).
var ErrEmpty = errors.New("no usable entries (not a blocklist?)")

// Parse reads a list. Understood: "||name^" (with subdomains), hosts lines
// ("0.0.0.0 name"), plain names; comments (#, !) and everything else
// (exceptions, cosmetic or URL rules) are skipped.
func Parse(name string, r io.Reader) (*List, error) { return parse(name, r, false) }

// ParseAllow reads an allowlist: like Parse, and AdGuard exceptions
// ("@@||name^") count as entries.
func ParseAllow(name string, r io.Reader) (*List, error) { return parse(name, r, true) }

func parse(name string, r io.Reader, allow bool) (*List, error) {
	var keys []uint64
	truncated := false
	br := bufio.NewReaderSize(r, MaxLine)
	for {
		line, long, err := br.ReadLine()
		if long { // skip the rest of an overlong line
			for long && err == nil {
				_, long, err = br.ReadLine()
			}
			line = nil
		}
		if d, sub := parseLine(string(line), allow); d != "" {
			k := hashName(d)
			if sub {
				k |= 1
			}
			keys = append(keys, k)
			if len(keys) >= MaxEntries {
				truncated = true
				break
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	if len(keys) == 0 {
		return nil, ErrEmpty
	}
	l := build(name, keys)
	l.Truncated = truncated
	return l, nil
}

func parseLine(s string, allow bool) (string, bool) {
	s = strings.TrimSpace(s)
	if allow {
		s = strings.TrimPrefix(s, "@@")
	}
	if s == "" || s[0] == '#' || s[0] == '!' || s[0] == '@' {
		return "", false
	}
	// inline comments only after white space ("0.0.0.0 name # note"): a '#'
	// inside a word is a cosmetic or scriptlet rule ("site.example##.ad",
	// uBlock Origin/EasyList) and must not turn into a block of the site
	for i := 1; i < len(s); i++ {
		if s[i] == '#' && (s[i-1] == ' ' || s[i-1] == '\t') {
			s = strings.TrimSpace(s[:i])
			break
		}
	}
	if rest, ok := strings.CutPrefix(s, "||"); ok {
		rest, opts, _ := strings.Cut(rest, "$")
		if opts != "" && opts != "important" {
			return "", false // client/type specific: not for DNS
		}
		d, ok := strings.CutSuffix(rest, "^")
		if !ok {
			return "", false
		}
		return Normalize(d), true
	}
	f := strings.Fields(s)
	switch {
	case len(f) == 1:
		return Normalize(f[0]), false
	case len(f) == 2 && (f[0] == "0.0.0.0" || f[0] == "127.0.0.1" || f[0] == "::" || f[0] == "::1"):
		return Normalize(f[1]), false
	}
	return "", false
}

// Normalize lowercases a name and returns "" for anything that is not a
// plain DNS name with at least two labels.
func Normalize(d string) string {
	d = strings.TrimSuffix(strings.ToLower(d), ".")
	if len(d) == 0 || len(d) > 253 || !strings.Contains(d, ".") || d == "localhost" {
		return ""
	}
	for i := 0; i < len(d); i++ {
		c := d[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_') {
			return ""
		}
	}
	if d[0] == '.' || strings.Contains(d, "..") {
		return ""
	}
	return d
}

// Has reports whether name (normalized) is blocked by l.
func (l *List) Has(name string) bool {
	if len(l.keys) == 0 {
		return false
	}
	if found, _ := l.lookup(hashName(name)); found {
		return true
	}
	for i := 0; i < len(name); i++ {
		if name[i] == '.' {
			if _, sub := l.lookup(hashName(name[i+1:])); sub {
				return true
			}
		}
	}
	return false
}

// Filter is an immutable snapshot: the lists of each level and the allowlist.
type Filter struct {
	levels map[string][]*List
	allow  []string
	// allowLists: downloaded lists of names that are never blocked.
	allowLists []*List
}

// NewFilter builds a filter (levels: level -> lists).
func NewFilter(levels map[string][]*List, allow []string) *Filter {
	return &Filter{levels: levels, allow: allow}
}

// WithAllowLists returns a copy that also never blocks the names of ls
// (platform code that parses its own allowlist files).
func (f *Filter) WithAllowLists(ls []*List) *Filter {
	if f == nil {
		return nil
	}
	c := *f
	c.allowLists = append(append([]*List(nil), f.allowLists...), ls...)
	return &c
}

// Check returns the list that blocks name at level, or "".
func (f *Filter) Check(level, name string) string {
	if f == nil {
		return ""
	}
	lists := f.levels[level]
	if len(lists) == 0 {
		return ""
	}
	for _, a := range f.allow {
		if name == a || strings.HasSuffix(name, "."+a) {
			return ""
		}
	}
	for _, l := range lists {
		if l.Has(name) {
			for _, a := range f.allowLists {
				if a.Has(name) {
					return ""
				}
			}
			return l.Name
		}
	}
	return ""
}
