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
	"io"
	"strings"
)

// List is one parsed blocklist. A value of true means the name and all its
// subdomains are blocked ("||example.com^"), false only the name itself
// (hosts files, plain names).
type List struct {
	Name    string
	entries map[string]bool
}

// Len is the number of entries.
func (l *List) Len() int { return len(l.entries) }

// MaxLine: longer lines are skipped (a valid name is at most 253 bytes).
const MaxLine = 4096

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
	l := &List{Name: name, entries: map[string]bool{}}
	br := bufio.NewReaderSize(r, MaxLine)
	for {
		line, long, err := br.ReadLine()
		if long { // skip the rest of an overlong line
			for long && err == nil {
				_, long, err = br.ReadLine()
			}
			line = nil
		}
		if d, sub := parseLine(string(line), allow); d != "" && (sub || !l.entries[d]) {
			l.entries[d] = sub
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	if len(l.entries) == 0 {
		return nil, ErrEmpty
	}
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
	if _, ok := l.entries[name]; ok {
		return true
	}
	for i := 0; i < len(name); i++ {
		if name[i] == '.' {
			if l.entries[name[i+1:]] {
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
