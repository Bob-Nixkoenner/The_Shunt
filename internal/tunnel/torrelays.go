package tunnel

import (
	"bufio"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// TorRelays reads the addresses of all relays out of the consensus tor
// cached in dataDir (cached-microdesc-consensus, else cached-consensus):
// the "r" line's IPv4 address and the "a" lines' IPv6 addresses. Used by
// the emergency mode (tor-all), which lets tor reach nothing else.
func TorRelays(dataDir string) ([]netip.Prefix, error) {
	var f *os.File
	var err error
	for _, n := range []string{"cached-microdesc-consensus", "cached-consensus"} {
		if f, err = os.Open(filepath.Join(dataDir, n)); err == nil {
			break
		}
	}
	if f == nil {
		return nil, errors.New("tor has no cached consensus yet")
	}
	defer f.Close()
	seen := map[netip.Prefix]bool{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		l := sc.Text()
		switch {
		case strings.HasPrefix(l, "r "):
			// r nick identity digest date time IP ORPort DirPort
			if fl := strings.Fields(l); len(fl) >= 7 {
				if a, err := netip.ParseAddr(fl[6]); err == nil {
					seen[netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen())] = true
				}
			}
		case strings.HasPrefix(l, "a "):
			if ap, err := netip.ParseAddrPort(strings.TrimSpace(l[2:])); err == nil {
				a := ap.Addr().Unmap()
				seen[netip.PrefixFrom(a, a.BitLen())] = true
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return sortPrefixes(seen), nil
}

// BridgeDsts returns the addresses of bridge lines (as ExpandBridges
// yields them). opaque: a bridge hides its real destination (snowflake,
// meek, webtunnel go through a broker, a CDN or a domain), so the addresses
// cannot be pinned.
func BridgeDsts(bridges []string) (dst []netip.Prefix, opaque bool) {
	seen := map[netip.Prefix]bool{}
	for _, b := range bridges {
		f := strings.Fields(strings.TrimPrefix(strings.TrimSpace(b), "Bridge "))
		if len(f) == 0 {
			continue
		}
		if !strings.ContainsAny(f[0], ".:[") { // a transport name
			switch {
			case f[0] == "snowflake", f[0] == "webtunnel", strings.HasPrefix(f[0], "meek"):
				opaque = true
				continue
			}
			f = f[1:]
		}
		if len(f) == 0 {
			continue
		}
		if ap, err := netip.ParseAddrPort(f[0]); err == nil {
			a := ap.Addr().Unmap()
			seen[netip.PrefixFrom(a, a.BitLen())] = true
		}
	}
	return sortPrefixes(seen), opaque
}

func sortPrefixes(m map[netip.Prefix]bool) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(m))
	for p := range m {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}
