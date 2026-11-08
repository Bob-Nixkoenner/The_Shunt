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

// The boot-time copies share the default sublayer with the kill switch's
// boot-time copies (LAN permit 11, DHCP/ND permit 12): the drops must weigh
// more than those, the own DHCP/ND permits more than the drops.
func TestQuietWeightBoot(t *testing.T) {
	const ksLAN, ksDHCP = 11, 12
	for _, boot := range []bool{false, true} {
		for _, r := range QuietRules(nil) {
			w := QuietWeight(r, boot)
			if w > 15 {
				t.Fatalf("weight %d out of range", w)
			}
			if r.Permit && w <= QuietWeight(QuietRule{}, boot) {
				t.Errorf("boot=%v: permit %+v not above the drops", boot, r)
			}
			if boot && !r.Permit && (w <= ksLAN || w <= ksDHCP) {
				t.Errorf("boot drop %+v weight %d not above the kill switch permits", r, w)
			}
		}
	}
}
