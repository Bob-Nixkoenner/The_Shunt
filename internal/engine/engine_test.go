package engine

import (
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
)

func TestStartGuard(t *testing.T) {
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
app = ["firefox", "curl"]
route = "block"
[[rule]]
app = ["flatpak:org.example.App", "same-rule"]
route = "tunnel:vps"
[[rule]]
app = ["after-flatpak"]
route = "tunnel:vps"
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
	mark := StartEntry{Mark: vps}
	hold := StartEntry{Hold: true}
	want := map[string]StartEntry{
		// whole programs get the mark; names are cut to comm's 15 bytes
		"firefox":         mark,
		"a-very-long-pro": mark,
		"same-rule":       mark,
		// args, ports and exe paths (by base name) need the watcher; curl's
		// later whole-program rule does not change that (first rule wins)
		"curl": hold,
		"wget": hold,
		"foo":  hold,
		// a Flatpak program may carry any name; a domain rule applies to
		// every program, also one not yet in its group
		"after-flatpak": hold,
		"thunderbird":   hold,
	}
	got := p.StartGuard()
	if len(got) != len(want) {
		t.Errorf("got %v", got)
	}
	for n, w := range want {
		if got[n] != w {
			t.Errorf("%s: got %+v, want %+v", n, got[n], w)
		}
	}
}

func TestStartGuardFilterLevel(t *testing.T) {
	c, err := config.Parse(`
[daemon]
default_route = "direct"
[tunnel.vps]
config = "x"
dns_filter = "low"
[[rule]]
app = ["kid-browser"]
route = "tunnel:vps"
dns_filter = "paranoid"
[[rule]]
app = ["filter-only"]
dns_filter = "off"
`)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Compile(c, "shunt", map[string]TunnelInfo{"vps": {Iface: "sh-vps", HasV4: true}})
	if err != nil {
		t.Fatal(err)
	}
	// queries before the move would skip the rule's own filter level
	g := p.StartGuard()
	for _, n := range []string{"kid-browser", "filter-only"} {
		if e := g[n]; !e.Hold {
			t.Errorf("%s: own DNS filter level must hold, got %+v", n, e)
		}
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
