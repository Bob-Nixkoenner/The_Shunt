package defense

import (
	"net/netip"
	"testing"
)

func TestNeighEntry(t *testing.T) {
	ip := netip.MustParseAddr("192.168.1.1")
	mac := []byte{0xAA, 0xbb, 0x0c, 1, 2, 0xff}
	a, m, ok := neighEntry(ip, mac, 5)
	if !ok || a != ip || m != "aa:bb:0c:01:02:ff" {
		t.Fatal(a, m, ok)
	}
	for _, st := range []int{nlUnreachable, nlIncomplete} {
		if _, _, ok := neighEntry(ip, mac, st); ok {
			t.Errorf("state %d must be skipped", st)
		}
	}
	if _, _, ok := neighEntry(ip, mac[:4], 5); ok {
		t.Error("short MAC")
	}
	if _, _, ok := neighEntry(netip.Addr{}, mac, 5); ok {
		t.Error("no IP")
	}
}

// the table rows feed the gateway watch: a new MAC for the gateway is one event
func TestNeighEntryFeedsGatewayWatch(t *testing.T) {
	gw := newGWWatch("192.168.1.1", "aa:bb:cc:dd:ee:01")
	ip := netip.MustParseAddr("::ffff:192.168.1.1")
	a, m, _ := neighEntry(ip, []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}, 5)
	if _, hit := gw.Feed(a, m); hit {
		t.Fatal("same MAC")
	}
	a, m, _ = neighEntry(ip, []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02}, 4)
	if ev, hit := gw.Feed(a, m); !hit || ev.Kind != KindARP {
		t.Fatal("new MAC must report")
	}
}
