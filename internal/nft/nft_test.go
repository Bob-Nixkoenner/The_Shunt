package nft

import (
	"flag"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/Bob-Nixkoenner/the_shunt/internal/engine"
)

var update = flag.Bool("update", false, "rewrite golden files")

func plan(t *testing.T) *engine.Plan {
	t.Helper()
	c, err := config.Parse(`
[daemon]
default_route = "tunnel:vps"
[tunnel.vps]
config = "vps.conf"
[tunnel.home]
config = "home.conf"
[group.torrent]
[[rule]]
name = "ssh direct"
port = ["tcp/22"]
route = "direct"
[[rule]]
name = "streaming direct"
domain = ["netflix.com", "*.nflxvideo.net"]
port = ["tcp/443"]
route = "direct"
[[rule]]
name = "homelab"
cidr = ["192.168.1.0/24", "fd00:1::/64"]
route = "tunnel:home"
[[rule]]
name = "torrent"
group = ["torrent"]
port = ["udp/6881-6889", "tcp/6881"]
route = "tunnel:vps"
`)
	if err != nil {
		t.Fatal(err)
	}
	all := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}
	p, err := engine.Compile(c, "system.slice/shuntd.service", map[string]engine.TunnelInfo{
		"vps":  {Iface: "sh-vps", HasV4: true, AllowedIPs: all},
		"home": {Iface: "sh-home", HasV4: true, HasV6: true, AllowedIPs: all},
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRenderGolden(t *testing.T) {
	got, err := Render(plan(t))
	if err != nil {
		t.Fatal(err)
	}
	const golden = "testdata/ruleset.nft"
	if *update {
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("ruleset differs from %s (run with -update after checking):\n%s", golden, got)
	}
}

func TestRenderRejectsInjection(t *testing.T) {
	p := plan(t)
	p.DaemonGroup.Path = `x" accept; flush ruleset; "`
	if _, err := Render(p); err == nil {
		t.Fatal("expected error for unsafe cgroup path")
	}
}

func TestRuleOrder(t *testing.T) {
	got, _ := Render(plan(t))
	ssh := strings.Index(got, "dport { 22 }")
	via := strings.Index(got, `apps/via/tunnel-vps`)
	if ssh < 0 || via < 0 || ssh > via {
		t.Error("explicit rules must come before implicit --via rules")
	}
}
