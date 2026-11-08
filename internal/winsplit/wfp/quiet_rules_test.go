package wfp

import (
	"net/netip"
	"testing"
)

func TestQuietRulesOrder(t *testing.T) {
	r := QuietRules([]netip.Addr{netip.MustParseAddr("192.168.1.255"), netip.MustParseAddr("192.168.1.255"), netip.MustParseAddr("255.255.255.255")})
	seenDrop := false
	var drops, permits int
	for _, x := range r {
		if x.Permit {
			permits++
			if seenDrop {
				t.Fatal("permit after a drop")
			}
			continue
		}
		seenDrop = true
		drops++
	}
	if permits != 7 { // DHCP, DHCPv6, 5 x ND
		t.Errorf("permits = %d", permits)
	}
	if drops != 2*8+3+1 { // ports per family, multicast/broadcast, subnet broadcast
		t.Errorf("drops = %d", drops)
	}
	has := func(p string) bool {
		for _, x := range r {
			if !x.Permit && x.Prefix.IsValid() && x.Prefix.String() == p {
				return true
			}
		}
		return false
	}
	for _, p := range []string{"224.0.0.0/4", "ff00::/8", "255.255.255.255/32", "192.168.1.255/32"} {
		if !has(p) {
			t.Errorf("missing drop %s", p)
		}
	}
}

func TestBroadcastAddrs(t *testing.T) {
	got := BroadcastAddrs([]netip.Prefix{
		netip.MustParsePrefix("192.168.1.20/24"),
		netip.MustParsePrefix("10.1.2.3/16"),
		netip.MustParsePrefix("169.254.5.5/32"),
		netip.MustParsePrefix("fe80::1/64"),
	})
	if len(got) != 2 || got[0].String() != "192.168.1.255" || got[1].String() != "10.1.255.255" {
		t.Errorf("got %v", got)
	}
}
