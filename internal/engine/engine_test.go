package engine

import (
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
)

func TestStartMarks(t *testing.T) {
	c, err := config.Parse(`
[daemon]
default_route = "direct"
[tunnel.vps]
config = "x"
[[rule]]
app = ["firefox", "a-very-long-program-name"]
route = "tunnel:vps"
[[rule]]
app = ["curl"]
args = ["--special"]
route = "tunnel:vps"
[[rule]]
app = ["wget"]
port = ["tcp/443"]
route = "tunnel:vps"
[[rule]]
app = ["exe:/usr/bin/foo"]
route = "block"
[[rule]]
app = ["firefox"]
route = "block"
[[rule]]
domain = ["netflix.com"]
route = "direct"
[[rule]]
app = ["thunderbird"]
route = "tunnel:vps"
`)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Compile(c, "shunt", map[string]TunnelInfo{"vps": {Iface: "sh-vps", HasV4: true}})
	if err != nil {
		t.Fatal(err)
	}
	vps := p.RouteByName("tunnel:vps").Mark
	got := p.StartMarks()
	// the second firefox rule is shadowed; names are cut to comm's 15 bytes
	if got["firefox"] != vps || got["a-very-long-pro"] != vps {
		t.Errorf("got %v", got)
	}
	// args, ports, exe selectors, and everything after the domain rule
	// (it applies to every program, also one not yet in its group)
	for _, n := range []string{"curl", "wget", "foo", "thunderbird", "a-very-long-program-name"} {
		if _, ok := got[n]; ok {
			t.Errorf("%s should not get a start mark: %v", n, got)
		}
	}
	if len(got) != 2 {
		t.Errorf("got %v", got)
	}
}

func TestTunnelGroups(t *testing.T) {
	c, err := config.Parse(`
[daemon]
default_route = "direct"
[tunnel.vps]
config = "x"
[[rule]]
app = ["firefox"]
route = "tunnel:vps"
[[rule]]
app = ["steam"]
route = "direct"
[[rule]]
app = ["telegram"]
route = "block"
`)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Compile(c, "shunt", map[string]TunnelInfo{"vps": {Iface: "sh-vps", HasV4: true}})
	if err != nil {
		t.Fatal(err)
	}
	got := p.TunnelGroups()
	// the tunnel app's group and the via-group of `shunt run --via`; not the
	// direct or blocked apps
	names := map[string]bool{}
	for _, g := range got {
		names[g.Name] = true
	}
	if len(got) != 2 || !names["app:rule 1"] || !names["via:tunnel:vps"] {
		t.Errorf("got %v", got)
	}
}
