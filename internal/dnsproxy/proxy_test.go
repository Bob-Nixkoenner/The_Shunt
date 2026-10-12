package dnsproxy

import (
	"net/netip"
	"testing"
)

func TestRoutable(t *testing.T) {
	for s, want := range map[string]bool{
		"0.0.0.0": false, "0.1.2.3": false, "127.0.0.1": false, "169.254.1.1": false,
		"224.0.0.1": false, "255.255.255.255": false, "::": false, "::1": false, "fe80::1": false,
		"ff02::1": false, "::ffff:127.0.0.1": false,
		"93.184.216.34": true, "192.168.1.10": true, "10.0.0.1": true, "2606:4700::1": true,
	} {
		if got := Routable(netip.MustParseAddr(s)); got != want {
			t.Errorf("%s: got %v", s, got)
		}
	}
}
