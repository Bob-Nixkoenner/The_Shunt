package netdetect

import (
	"net/netip"
	"testing"
)

func TestPublicAddresses(t *testing.T) {
	cases := []struct {
		a      string
		v4, v6 bool
	}{
		{"192.0.2.10", true, false}, // documentation ranges count as public
		{"198.51.100.7", true, false},
		{"203.0.113.9", true, false},
		{"2001:db8::1", false, true},
		{"10.1.2.3", false, false},
		{"172.16.0.1", false, false},
		{"192.168.1.5", false, false},
		{"100.64.0.1", false, false}, // CGNAT
		{"100.127.255.254", false, false},
		{"100.128.0.1", true, false},
		{"169.254.1.1", false, false},
		{"127.0.0.1", false, false},
		{"0.1.2.3", false, false},
		{"224.0.0.1", false, false},
		{"fd12:3456::1", false, false}, // ULA
		{"fe80::1", false, false},
		{"::1", false, false},
		{"ff02::1", false, false},
		{"::ffff:192.0.2.1", true, false},
	}
	for _, c := range cases {
		v4, v6 := PublicIn([]netip.Addr{netip.MustParseAddr(c.a)})
		if v4 != c.v4 || v6 != c.v6 {
			t.Errorf("%s: got v4=%v v6=%v", c.a, v4, v6)
		}
	}
	v4, v6 := PublicIn([]netip.Addr{netip.MustParseAddr("192.168.0.2"), netip.MustParseAddr("2001:db8::5"), netip.MustParseAddr("fe80::2")})
	if v4 || !v6 {
		t.Errorf("mixed: v4=%v v6=%v", v4, v6)
	}
	if (Info{PublicV4: true}).Exposure() == (Info{}).Exposure() {
		t.Error("Exposure must differ")
	}
}
