package nft

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/Bob-Nixkoenner/the_shunt/internal/engine"
)

// M-06: held programs (all of apps/ask) and groups whose catch-all rule
// blocks may not use a SOCKS exit; the first catch-all rule of a group
// decides, rules with destinations or ports do not.
func TestExitDeny(t *testing.T) {
	c, err := config.Parse(`
[daemon]
default_route = "direct"
[tunnel.vps]
config = "vps.conf"
socks = "127.0.0.1:1080"
[group.blocked]
[group.web]
[group.early]
[[rule]]
name = "web to the tunnel first"
group = ["early"]
route = "tunnel:vps"
[[rule]]
name = "web: ssh blocked"
group = ["web"]
port = ["tcp/22"]
route = "block"
[[rule]]
name = "no net"
group = ["blocked", "early"]
route = "block"
`)
	if err != nil {
		t.Fatal(err)
	}
	all := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	p, err := engine.Compile(c, "system.slice/shuntd.service", map[string]engine.TunnelInfo{
		"vps": {Iface: "sh-vps", HasV4: true, AllowedIPs: all, Addrs: []netip.Addr{netip.MustParseAddr("10.166.0.12")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, g := range ExitDeny(p) {
		got[g.Path] = true
	}
	root := "system.slice/shuntd.service/apps/"
	for _, want := range []string{root + "ask", root + "g/blocked", root + "via/block"} {
		if !got[want] {
			t.Errorf("%s not denied: %v", want, got)
		}
	}
	for _, not := range []string{root + "g/web", root + "g/early", root + "via/tunnel-vps", root + "via/direct"} {
		if got[not] {
			t.Errorf("%s denied: %v", not, got)
		}
	}
}

func TestRenderGuardExits(t *testing.T) {
	ask := engine.Group{Path: "system.slice/shuntd.service/apps/ask"}
	s, err := RenderGuard(Guard{Exits: []ExitGuard{
		{Addr: netip.MustParseAddrPort("127.0.0.1:1080"), Deny: []engine.Group{ask}},
		{Addr: netip.MustParseAddrPort("[::1]:1081"), Deny: []engine.Group{ask}, Users: true, UIDs: []uint32{1001, 1000, 1001}},
		{Addr: netip.MustParseAddrPort("127.0.0.2:1082"), Users: true},
		{Addr: netip.MustParseAddrPort("127.0.0.3:1083")}, // nothing to keep off: no rules
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ip daddr 127.0.0.1 tcp dport 1080 jump exit0",
		"ip6 daddr ::1 tcp dport 1081 jump exit1",
		"ip daddr 127.0.0.2 tcp dport 1082 jump exit2",
		"chain exit0 {\n\t\tsocket cgroupv2 level 4 \"system.slice/shuntd.service/apps/ask\" counter reject with tcp reset\n\t}",
		"meta skuid != { 1000, 1001 } counter reject with tcp reset",
		"chain exit2 {\n\t\tcounter reject with tcp reset\n\t}",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("guard lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "1083") {
		t.Errorf("an exit without restrictions needs no rule:\n%s", s)
	}
	if _, err := RenderGuard(Guard{Exits: []ExitGuard{{Addr: netip.MustParseAddrPort("127.0.0.1:1080"), Deny: []engine.Group{{Path: `x" accept`}}}}}); err == nil {
		t.Error("unsafe cgroup path accepted")
	}
}

// With shuntd stopped the DNS listener ports are rejected (UDP and TCP, so
// resolvers give up at once), Tor ports and exits dropped.
func TestRenderGuardStopped(t *testing.T) {
	s, err := RenderGuard(Guard{TorPorts: []int{53001}, DNSPorts: []int{5300, 5301}, Socks: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:1080")}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ip daddr 127.0.0.0/8 meta l4proto { tcp, udp } th dport { 5300, 5301 } reject with icmpx port-unreachable",
		"ip6 daddr ::1 meta l4proto { tcp, udp } th dport { 5300, 5301 } reject with icmpx port-unreachable",
		"ip daddr 127.0.0.0/8 tcp dport { 53001 } drop",
		"ip daddr 127.0.0.1 tcp dport 1080 drop",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("guard lacks %q:\n%s", want, s)
		}
	}
	if empty, _ := RenderGuard(Guard{}); strings.Contains(empty, "chain") {
		t.Errorf("empty guard must only delete the table: %s", empty)
	}
}

// At boot (`shuntd lockdown`) every configured exit address is closed
// until shuntd binds it; without exits the guard only deletes the table.
func TestBootGuard(t *testing.T) {
	c, err := config.Parse("[tunnel.a]\nconfig = \"a.conf\"\nsocks = \"127.0.0.1:1080\"\n[tunnel.b]\nconfig = \"b.conf\"\nsocks = \"[::1]:1081\"\n[tunnel.c]\nconfig = \"c.conf\"\n")
	if err != nil {
		t.Fatal(err)
	}
	s := BootGuard(c)
	for _, want := range []string{"ip daddr 127.0.0.1 tcp dport 1080 drop", "ip6 daddr ::1 tcp dport 1081 drop"} {
		if !strings.Contains(s, want) {
			t.Errorf("boot guard lacks %q:\n%s", want, s)
		}
	}
	c, _ = config.Parse("[tunnel.c]\nconfig = \"c.conf\"\n")
	if s := BootGuard(c); strings.Contains(s, "chain") {
		t.Errorf("no exit: %s", s)
	}
}
