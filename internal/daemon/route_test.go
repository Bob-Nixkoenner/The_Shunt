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
