package defense

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

// IgnoreEntry is one device the user does not want reported as an attacker
// (their own Syncthing peer that looks for this machine, a printer, ...).
// Unlike Config.Never ("never block") an ignored source also produces no
// event, no heat and no block for scans, brute force and decoy hits. Bad-list
// hits (reputation) stay visible. Peers of a VPN are never ignored by
// themselves: only entries the user wrote count.
type IgnoreEntry struct {
	Addr  string `json:"addr" toml:"addr"`                       // address or CIDR
	Name  string `json:"name,omitempty" toml:"name,omitempty"`   // note of the user
	Ports []int  `json:"ports,omitempty" toml:"ports,omitempty"` // local ports; empty = all
}

// Limits of the ignore list.
const (
	MaxIgnoreEntries = 64
	MaxIgnorePorts   = 16
	MaxIgnoreName    = 64
)

// CleanText cuts s to max runes and drops everything that is not printable
// (control characters, line breaks, format characters). Used for notes of
// the user and for names learned from the network (untrusted input).
func CleanText(s string, max int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if r == utf8.RuneError || !unicode.IsPrint(r) || unicode.Is(unicode.Cf, r) {
			continue
		}
		if n >= max {
			break
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}

// ValidateIgnore checks the list from a config or an API body.
func ValidateIgnore(in []IgnoreEntry) error {
	if len(in) > MaxIgnoreEntries {
		return fmt.Errorf("defense.ignore: at most %d entries", MaxIgnoreEntries)
	}
	for i, e := range in {
		p, ok := parsePrefix(strings.TrimSpace(e.Addr))
		if !ok {
			return fmt.Errorf("defense.ignore[%d]: %q is no address or CIDR", i, e.Addr)
		}
		if p.Addr().IsUnspecified() || p.Addr().IsMulticast() {
			return fmt.Errorf("defense.ignore[%d]: %q is not a unicast address", i, e.Addr)
		}
		// a whole continent of sources must not be silenced by one typo
		if (p.Addr().Is4() && p.Bits() < 8) || (!p.Addr().Is4() && p.Bits() < 32) {
			return fmt.Errorf("defense.ignore[%d]: %q is too wide a range", i, e.Addr)
		}
		if utf8.RuneCountInString(e.Name) > MaxIgnoreName || CleanText(e.Name, MaxIgnoreName+1) != strings.TrimSpace(e.Name) {
			return fmt.Errorf("defense.ignore[%d]: the name is too long or has odd characters (at most %d)", i, MaxIgnoreName)
		}
		if len(e.Ports) > MaxIgnorePorts {
			return fmt.Errorf("defense.ignore[%d]: at most %d ports", i, MaxIgnorePorts)
		}
		seen := map[int]bool{}
		for _, po := range e.Ports {
			if po < 1 || po > 65535 {
				return fmt.Errorf("defense.ignore[%d]: port %d out of range", i, po)
			}
			if seen[po] {
				return fmt.Errorf("defense.ignore[%d]: port %d twice", i, po)
			}
			seen[po] = true
		}
	}
	return nil
}

type ignoreRule struct {
	p     netip.Prefix
	ports map[int]bool
}

// IgnoreSet answers whether a source (and local port) is on the ignore list.
type IgnoreSet struct {
	mu    sync.RWMutex
	rules []ignoreRule
}

// Set replaces the rules (invalid entries are skipped).
func (s *IgnoreSet) Set(in []IgnoreEntry) {
	var rules []ignoreRule
	for _, e := range in {
		p, ok := parsePrefix(strings.TrimSpace(e.Addr))
		if !ok {
			continue
		}
		r := ignoreRule{p: p}
		if len(e.Ports) > 0 {
			r.ports = map[int]bool{}
			for _, po := range e.Ports {
				r.ports[po] = true
			}
		}
		rules = append(rules, r)
	}
	s.mu.Lock()
	s.rules = rules
	s.mu.Unlock()
}

// Match reports whether traffic from a to local port (0 = unknown) is ignored.
// An entry limited to ports never matches an unknown port.
func (s *IgnoreSet) Match(a netip.Addr, port int) bool {
	a = a.Unmap()
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.rules {
		if r.p.Contains(a) && (r.ports == nil || r.ports[port]) {
			return true
		}
	}
	return false
}

// ignoredKind lists the events a source on the ignore list does not cause.
// Reputation hits are deliberately not among them.
func ignoredKind(k Kind) bool {
	switch k {
	case KindScan, KindBruteForce, KindDecoyHit, KindTarpit, KindCowrie, KindBait:
		return true
	}
	return false
}
