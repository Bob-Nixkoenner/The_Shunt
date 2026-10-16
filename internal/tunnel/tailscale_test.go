package tunnel

import (
	"net/netip"
	"testing"
)

func TestTailscaleAddrs(t *testing.T) {
	block := netip.MustParsePrefix("198.18.0.0/15")
	h1, p1 := TailscaleAddrs("work")
	h2, _ := TailscaleAddrs("work")
	if h1 != h2 {
		t.Fatal("not deterministic")
	}
	if !block.Contains(h1) || !block.Contains(p1) {
		t.Fatalf("%v %v outside %v", h1, p1, block)
	}
	if p1 != h1.Next() || netip.PrefixFrom(h1, 30).Masked() != netip.PrefixFrom(p1, 30).Masked() {
		t.Fatalf("host and peer must share a /30: %v %v", h1, p1)
	}
}
