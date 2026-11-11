package daemon

import (
	"net/netip"
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/api"
)

func TestReachableFromInternet(t *testing.T) {
	all := api.OpenPort{Reach: "all", Exposed: true}
	lan := api.OpenPort{Reach: "iface", Exposed: true}
	a := netip.MustParseAddr("0.0.0.0")
	priv := netip.MustParseAddr("192.168.1.5")
	pub := netip.MustParseAddr("203.0.113.5")
	cases := []struct {
		name         string
		p            api.OpenPort
		a            netip.Addr
		unfilt, pubU bool
		want         bool
	}{
		{"all, no filter, private net", all, a, true, false, true},
		{"all, filter, private net", all, a, false, false, false},
		{"all, filter closed but public net and not blocked", all, a, false, true, true},
		{"blocked by the firewall", api.OpenPort{Reach: "all", Exposed: true, Blocked: true}, a, true, true, false},
		{"lan only", api.OpenPort{Reach: "all", Exposed: true, LANOnly: true}, a, true, true, false},
		{"private address only, public net", lan, priv, true, true, false},
		{"bound to the public address", lan, pub, true, false, true},
		{"localhost", api.OpenPort{Reach: "localhost"}, a, true, true, false},
	}
	for _, c := range cases {
		if got := reachableFromInternet(c.p, c.a, c.unfilt, c.pubU); got != c.want {
			t.Errorf("%s: got %v", c.name, got)
		}
	}
}
