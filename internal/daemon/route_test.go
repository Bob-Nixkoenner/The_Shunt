package daemon

import (
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/Bob-Nixkoenner/the_shunt/internal/engine"
)

func TestFromRoute(t *testing.T) {
	direct := &engine.Route{Route: config.Route{Kind: config.RouteDirect}}
	vps := &engine.Route{Route: config.Route{Kind: config.RouteTunnel, Tunnel: "vps"}}
	g := engine.Group{Name: "browser", Path: "shunt/apps/g/browser"}
	groupRoute := func(engine.Group) string { return "tunnel:vps" }
	for _, c := range []struct {
		cg   string
		def  *engine.Route
		want string
	}{
		{"shunt/apps/g/browser", direct, "tunnel:vps"},
		{"shunt/apps/g/browser/sub", direct, "tunnel:vps"},
		{"shunt/apps/ask/p3", direct, "block"},      // held by the app firewall
		{"user.slice/app.scope", direct, ""},        // default direct: free
		{"user.slice/app.scope", vps, "tunnel:vps"}, // default tunnel: leaving needs manage
		{"shunt/apps/free", vps, "tunnel:vps"},      // released to the default route
	} {
		p := &engine.Plan{CgroupRoot: "shunt", Groups: []engine.Group{g}, DefaultRoute: c.def}
		if got := fromRoute(c.cg, p, groupRoute); got != c.want {
			t.Errorf("%s (default %s): got %q, want %q", c.cg, c.def, got, c.want)
		}
	}
}

func TestInDefaultRoute(t *testing.T) {
	p := &engine.Plan{CgroupRoot: "shunt", Groups: []engine.Group{{Name: "browser", Path: "shunt/apps/g/browser"}}}
	for cg, want := range map[string]bool{
		"user.slice/app.scope":     true,
		"shunt/apps/free":          true,
		"shunt/apps/g/browser":     false, // placed on purpose: leaving is an escape
		"shunt/apps/g/browser/sub": false,
		"shunt/apps/ask/p3":        false, // held by the app firewall
	} {
		if got := inDefaultRoute(cg, p); got != want {
			t.Errorf("%s: got %v, want %v", cg, got, want)
		}
	}
}

func TestTunnelHop(t *testing.T) {
	c := &config.Config{Tunnels: map[string]config.Tunnel{
		"vps": {}, "home": {}, "tor": {Driver: "tor"},
	}}
	for _, x := range []struct {
		from, to string
		want     bool
	}{
		{"tunnel:vps", "tunnel:home", true},
		{"tunnel:vps", "direct", false},     // out of the tunnels: password
		{"tunnel:vps", "link:wifi", false},  // past the tunnels
		{"tunnel:tor", "tunnel:vps", false}, // leaving Tor costs anonymity
		{"tunnel:vps", "tunnel:tor", false},
		{"tunnel:vps", "tunnel:gone", false},
		{"block", "tunnel:vps", false},
	} {
		if got := tunnelHop(c, x.from, x.to); got != x.want {
			t.Errorf("%s -> %s: got %v, want %v", x.from, x.to, got, x.want)
		}
	}
	if tunnelHop(nil, "tunnel:vps", "tunnel:home") {
		t.Error("nil config must not allow")
	}
}
