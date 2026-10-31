package engine

import (
	"net/netip"
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
)

func TestCompileGateway(t *testing.T) {
	c, err := config.Parse(`
[daemon]
default_route = "tunnel:a"
[tunnel.a]
config = "a.conf"
[gateway]
enabled = true
[[gateway.group]]
name = "vms"
interfaces = ["virbr1", "br-b"]
route = "tunnel:a"
[[gateway.group]]
name = "bad"
interfaces = ["wlan0"]
route = "direct"
[[gateway.group]]
name = "off"
interfaces = ["br9"]
`)
	if err != nil {
		t.Fatal(err)
	}
	all := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	p, err := CompileOn(c, "u.slice", map[string]TunnelInfo{"a": {Iface: "sh-a", HasV4: true, AllowedIPs: all}}, "", map[string]string{"wifi": "wlan0"})
	if err != nil {
		t.Fatal(err)
	}
	g := p.Gateway
	if g == nil || len(g.Groups) != 2 {
		t.Fatalf("gateway %+v", g)
	}
	if g.Groups[0].Route.String() != "tunnel:a" || g.Groups[0].Ifaces[0] != "br-b" {
		t.Errorf("group 0: %+v", g.Groups[0])
	}
	if g.Groups[1].Route.Kind != config.RouteBlock {
		t.Errorf("no route must block, got %v", g.Groups[1].Route)
	}
	if len(g.Rejected) != 1 || g.Rejected[0] != "wlan0" {
		t.Errorf("an uplink must be rejected: %v", g.Rejected)
	}
	if len(g.Uplinks) != 2 { // sh-a, wlan0
		t.Errorf("uplinks %v", g.Uplinks)
	}
	c.Gateway.Enabled = false
	if p, _ = CompileOn(c, "u.slice", map[string]TunnelInfo{"a": {Iface: "sh-a"}}, "", nil); p.Gateway != nil {
		t.Error("gateway off still compiled")
	}
}
