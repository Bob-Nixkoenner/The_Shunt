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
	got := p.StartGuard(true)
	if len(got) != len(want) {
		t.Errorf("got %v", got)
	}
	for n, w := range want {
		if got[n] != w {
			t.Errorf("%s: got %+v, want %+v", n, got[n], w)
		}
	}
	// default levels: nothing held; whole-program rules mark (also after a
	// rule for every program, or by exe base name); argument and port rules
	// are left to the watcher (their mark would be wrong for other starts)
	soft := p.StartGuard(false)
	block := p.RouteByName("block").Mark
	wantSoft := map[string]StartEntry{
		"firefox": mark, "a-very-long-pro": mark,
		"foo": {Mark: block}, "after-flatpak": mark, "thunderbird": mark,
	}
	for n, w := range wantSoft {
		if soft[n] != w {
			t.Errorf("soft %s: got %+v, want %+v", n, soft[n], w)
		}
	}
	for _, n := range []string{"curl", "wget"} {
		if e, ok := soft[n]; ok {
			t.Errorf("soft %s: argument/port rule must be left out, got %+v", n, e)
		}
	}
	for n, e := range soft {
		if e.Hold {
			t.Errorf("soft %s held", n)
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
	g := p.StartGuard(true)
	for _, n := range []string{"kid-browser", "filter-only"} {
		if e := g[n]; !e.Hold {
			t.Errorf("%s: own DNS filter level must hold, got %+v", n, e)
		}
	}
	// default levels: nothing is held; a rule with a route marks, one
	// without (a filter level only) is left out
	g = p.StartGuard(false)
	var want uint32
	for _, r := range p.Rules {
		for _, a := range r.Apps {
			if a.Value == "kid-browser" && r.Route != nil {
				want = r.Route.Mark
			}
		}
	}
	if e, ok := g["kid-browser"]; !ok || e.Hold || e.Mark == 0 || e.Mark != want {
		t.Errorf("kid-browser without hold: got %+v", e)
	}
	if e, ok := g["filter-only"]; ok {
		t.Errorf("filter-only without hold must be left out, got %+v", e)
	}
	for n, e := range g {
		if e.Hold {
			t.Errorf("%s held although hold is off", n)
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
