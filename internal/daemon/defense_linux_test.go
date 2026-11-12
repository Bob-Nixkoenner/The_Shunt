package daemon

import (
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/Bob-Nixkoenner/the_shunt/internal/engine"
)

// The DNS check asks a public resolver only through a tunnel that is the
// default route and carries UDP. Every other default route means: not asked
// (it would travel over the local network).
func TestTunnelMark(t *testing.T) {
	route := func(k config.RouteKind, mark uint32, iface string, tor bool) *engine.Route {
		return &engine.Route{Route: config.Route{Kind: k}, Mark: mark, Iface: iface, Tor: tor}
	}
	tun := engine.MarkBase | 1
	for _, c := range []struct {
		name string
		r    *engine.Route
		ok   bool
	}{
		{"tunnel", route(config.RouteTunnel, tun, "wg0", false), true},
		{"no plan", nil, false},
		{"direct", route(config.RouteDirect, engine.MarkDirect, "", false), false},
		{"block", route(config.RouteBlock, engine.MarkBlock, "", false), false},
		{"link", route(config.RouteLink, engine.MarkBase|engine.LinkSlot, "wlan0", false), false},
		{"tor", route(config.RouteTunnel, tun, "", true), false},
		{"tunnel without interface", route(config.RouteTunnel, tun, "", false), false},
	} {
		mark, ok := tunnelMark(c.r)
		if ok != c.ok || ok && mark != tun {
			t.Errorf("%s: mark %#x ok=%v", c.name, mark, ok)
		}
	}
	d := &Daemon{}
	if _, ok := d.defenseTunnelMark(); ok {
		t.Error("no plan yet: nothing to ask through")
	}
	d.plan = &engine.Plan{DefaultRoute: route(config.RouteTunnel, tun, "wg0", false)}
	if mark, ok := d.defenseTunnelMark(); !ok || mark != tun {
		t.Errorf("tunnel default route: %#x %v", mark, ok)
	}
}
