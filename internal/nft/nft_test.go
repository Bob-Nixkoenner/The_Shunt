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
	block := strings.Index(got, `apps/via/block`)
	via := strings.Index(got, `apps/via/tunnel-vps`)
	ssh := strings.Index(got, "dport { 22 }")
	// block before everything; programs started in a route keep it unless a
	// rule says override_explicit
	if block < 0 || via < 0 || ssh < 0 || block > via || via > ssh {
		t.Errorf("order: block %d, via %d, ssh rule %d", block, via, ssh)
	}
}

func TestOverrideAndNetwork(t *testing.T) {
	c, err := config.Parse(`
[[network]]
name = "home"
ssid = ["Weifi_5G"]
default_route = "direct"

[[rule]]
name = "lan direct for everyone"
cidr = ["192.168.1.0/24"]
route = "direct"
override_explicit = true

[[rule]]
name = "home only"
cidr = ["10.1.0.0/16"]
route = "block"
network = ["home"]
`)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		network  string
		withHome bool
	}{{"home", true}, {"", false}} {
		p, err := engine.CompileOn(c, "shunt", nil, tc.network, nil)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := Render(p)
		block := strings.Index(got, `apps/via/block`)
		lan := strings.Index(got, "192.168.1.0/24")
		direct := strings.Index(got, `apps/via/direct"`)
		if !(block < lan && lan < direct) {
			t.Errorf("%q: override rule must sit between block and the via groups (%d %d %d)", tc.network, block, lan, direct)
		}
		if strings.Contains(got, "10.1.0.0/16") != tc.withHome {
			t.Errorf("%q: home-only rule present = %v", tc.network, !tc.withHome)
		}
	}
	if _, err := config.Parse("[[rule]]\ncidr = [\"1.2.3.4\"]\nroute = \"direct\"\nnetwork = [\"nope\"]\n"); err == nil {
		t.Error("unknown network profile accepted")
	}
}

func TestAllowLANLeakGuard(t *testing.T) {
	c, err := config.Parse("[tunnel.vps]\nconfig = \"vps.conf\"\nallow_lan = true\n")
	if err != nil {
		t.Fatal(err)
	}
	p, err := engine.Compile(c, "shunt", map[string]engine.TunnelInfo{"vps": {Iface: "sh-vps", HasV4: true}})
	if err != nil {
		t.Fatal(err)
	}
	out, err := Render(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`meta mark 0x530001 oifname != { "sh-vps", "lo" } meta nfproto ipv4 ip daddr != { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 } counter drop`,
		`meta nfproto ipv6 ip6 daddr != { fc00::/7, fe80::/10 } counter drop`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestAskRules(t *testing.T) {
	s, err := AskRules(map[string]engine.Group{"p2": {Name: "ask:firefox", Path: "shunt/apps/ask/p2"}})
	if err != nil {
		t.Fatal(err)
	}
	want := `add rule inet shunt ask_out socket cgroupv2 level 4 "shunt/apps/ask/p2" limit rate 5/second burst 10 packets log prefix "ask:p2 " group 5301`
	if !strings.Contains(s, "flush chain inet shunt ask_out\n") || !strings.Contains(s, want) {
		t.Errorf("got:\n%s", s)
	}
}
