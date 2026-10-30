package nft

import (
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/Bob-Nixkoenner/the_shunt/internal/engine"
)

func gatewayPlan(t *testing.T, defaultRoute string) *engine.Plan {
	t.Helper()
	c, err := config.Parse(`
[daemon]
default_route = "` + defaultRoute + `"
[tunnel.vps]
config = "vps.conf"
[tunnel.home]
config = "home.conf"
[gateway]
enabled = true
[[gateway.group]]
name = "vms"
interfaces = ["virbr1", "virbr2"]
route = "tunnel:vps"
[[gateway.group]]
name = "iot"
interfaces = ["br-iot"]
[[gateway.group]]
name = "guests"
interfaces = ["br-guest"]
route = "direct"
`)
	if err != nil {
		t.Fatal(err)
	}
	all := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	p, err := engine.CompileOn(c, "system.slice/shuntd.service", map[string]engine.TunnelInfo{
		"vps":  {Iface: "sh-vps", HasV4: true, AllowedIPs: all},
		"home": {Iface: "sh-home", HasV4: true, AllowedIPs: all},
	}, "", map[string]string{"wifi": "wlan0"})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestGatewayGolden(t *testing.T) {
	got, err := Render(gatewayPlan(t, "tunnel:home"))
	if err != nil {
		t.Fatal(err)
	}
	const golden = "testdata/gateway.nft"
	if *update {
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != got {
		t.Errorf("ruleset differs from %s (run with -update after checking):\n%s", golden, got)
	}
}

func TestGatewayRules(t *testing.T) {
	got, err := Render(gatewayPlan(t, "direct"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		// every group has its own route in mark_in, unicast only
		`iifname { "virbr1", "virbr2" } fib daddr type unicast ct state new ct mark and 0xffff00 != 0x530000 meta mark set 0x530002 ct mark set meta mark`,
		`iifname { "br-iot" } fib daddr type unicast ct state new ct mark and 0xffff00 != 0x530000 meta mark set 0x5300fe`,
		`iifname { "br-guest" } fib daddr type unicast ct state new ct mark and 0xffff00 != 0x530000 meta mark set 0x5300f0`,
		// no fallback: a tunnel group only passes tunnel/link marks
		`iifname { "virbr1", "virbr2" } meta mark != { 0x530001, 0x530002, 0x5300e0, 0x5300e1, 0x5300e2 } counter drop`,
		// block drops everything, IPv6 is dropped for all
		`iifname { "br-iot" } counter drop`,
		`iifname { "virbr1", "virbr2" } meta nfproto ipv6 counter drop`,
		`iifname { "br-guest" } meta nfproto ipv6 counter drop`,
		// groups apart, nothing new towards clients
		`iifname { "br-guest", "br-iot", "virbr1", "virbr2" } oifname { "br-guest", "br-iot", "virbr1", "virbr2" } counter drop`,
		`oifname { "br-guest", "br-iot", "virbr1", "virbr2" } ct state new counter drop`,
		// direct group gets NAT, the others through their route's marks
		`iifname { "br-guest" } oifname != { "br-guest" } masquerade`,
		// host: DHCP and DNS only
		`iifname { "br-guest", "br-iot", "virbr1", "virbr2" } counter drop`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	if strings.Contains(got, `"virbr1", "virbr2" } oifname != `) {
		t.Error("tunnel group must not get its own masquerade (the route's mark does it)")
	}
	// the default-route rule for forwarded traffic is not there (direct) and
	// no group is marked direct by accident: the tunnel group is never
	// allowed the direct or block mark
	if strings.Contains(got, "0x5300f0, ") || strings.Contains(got, "0x5300fe,") {
		t.Error("direct/block mark in the tunnel group's allowed marks")
	}
}

// Without the gateway mode the ruleset has none of its chains (the #48
// behaviour for forwarded traffic is untouched).
func TestNoGatewayNoChains(t *testing.T) {
	got, err := Render(plan(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"gw_fwd", "gw_in"} {
		if strings.Contains(got, s) {
			t.Errorf("%s without [gateway]", s)
		}
	}
}

func TestGatewayRejectsInjection(t *testing.T) {
	p := gatewayPlan(t, "direct")
	p.Gateway.Groups[0].Ifaces = []string{`x" drop; #`}
	if _, err := Render(p); err == nil {
		t.Error("unsafe interface name accepted")
	}
}
