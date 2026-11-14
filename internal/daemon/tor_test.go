package daemon

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/check"
	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/Bob-Nixkoenner/the_shunt/internal/nft"
	"github.com/Bob-Nixkoenner/the_shunt/internal/tunnel"
)

func TestNewIdentityErrors(t *testing.T) {
	d := &Daemon{cfg: &config.Config{Tunnels: map[string]config.Tunnel{
		"wg":  {Config: "a.conf"},
		"tor": {Driver: "tor"},
	}}, tunnels: map[string]tunnel.Device{}}
	if err := d.newIdentity("wg"); err == nil || !strings.Contains(err.Error(), "not a Tor tunnel") {
		t.Errorf("wireguard tunnel: %v", err)
	}
	if err := d.newIdentity("nope"); err == nil {
		t.Error("unknown tunnel accepted")
	}
	if err := d.newIdentity("tor"); err == nil || !strings.Contains(err.Error(), "not running") {
		t.Errorf("stopped tor: %v", err)
	}
}

// tor-all sends the default route and every rule (blocks excepted) through
// the Tor tunnel, including programs started in a route on purpose.
func TestTorAllPlan(t *testing.T) {
	conf := `[daemon]
socket = "/nonexistent/s.sock"
default_route = "direct"
[tunnel.tor]
driver = "tor"
[[rule]]
name = "ssh blocked"
port = ["tcp/22"]
route = "block"
[[rule]]
name = "web direct"
port = ["tcp/443"]
route = "direct"
[[rule]]
name = "mail"
app = ["thunderbird"]
route = "link:wifi"
`
	path := filepath.Join(t.TempDir(), "shunt.toml")
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, all := range []string{"", "tor", "missing"} {
		p, err := PrepareOn(path, "shunt", Env{Backend: newFake(), TorAll: all})
		if err != nil {
			t.Fatal(err)
		}
		on := all == "tor"
		want := func(def string) string {
			if on {
				return "tunnel:tor"
			}
			return def
		}
		if got := p.Plan.DefaultRoute.String(); got != want("direct") {
			t.Errorf("tor-all=%q: default route %s", all, got)
		}
		for _, r := range p.Plan.Rules {
			switch {
			case r.Name == "ssh blocked" && r.Route.String() != "block":
				t.Errorf("tor-all=%q: a block rule became %s", all, r.Route)
			case r.Name == "web direct" && r.Route.String() != want("direct"):
				t.Errorf("tor-all=%q: rule route %s", all, r.Route)
			case r.Name == "mail" && r.Route.String() != want("link:wifi"):
				t.Errorf("tor-all=%q: rule route %s", all, r.Route)
			case on && strings.HasPrefix(r.Name, "via:") && r.Route.Kind != config.RouteBlock && r.Route.String() != "tunnel:tor":
				t.Errorf("tor-all: via group %s still goes %s", r.Name, r.Route)
			}
			if on && r.Name == "mail" && r.ProxyPort == 0 {
				t.Error("tor-all: the rule has no proxy port of its own")
			}
		}
		warns := strings.Join(check.Texts(p.Notes), " ")
		if all != "" && !strings.Contains(warns, "tor-all") {
			t.Errorf("tor-all=%q: no warning", all)
		}
	}
}

func TestSetTorAllNeedsTorTunnel(t *testing.T) {
	d := &Daemon{ConfigPath: filepath.Join(t.TempDir(), "shunt.toml"), cfg: &config.Config{Tunnels: map[string]config.Tunnel{"wg": {Config: "a"}}}}
	if err := d.setTorAll(true, ""); err == nil || !strings.Contains(err.Error(), "no Tor tunnel") {
		t.Errorf("no tor tunnel: %v", err)
	}
	d.cfg.Tunnels["a"], d.cfg.Tunnels["b"] = config.Tunnel{Driver: "tor"}, config.Tunnel{Driver: "tor"}
	if err := d.setTorAll(true, ""); err == nil || !strings.Contains(err.Error(), "more than one") {
		t.Errorf("two tor tunnels: %v", err)
	}
	if err := d.setTorAll(true, "wg"); err == nil {
		t.Error("wireguard tunnel accepted as tor-all target")
	}
}

// M-04 (external report): a proxy port another program holds is reported, not
// silently skipped, so the caller can block it; a free one is bound.
func TestTorProxyPortTaken(t *testing.T) {
	conf := `[daemon]
socket = "/nonexistent/s.sock"
default_route = "direct"
[tunnel.tor]
driver = "tor"
[[rule]]
name = "via tor"
app = ["someapp"]
route = "tunnel:tor"
`
	path := filepath.Join(t.TempDir(), "shunt.toml")
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := PrepareOn(path, "shunt", Env{Backend: newFake()})
	if err != nil {
		t.Fatal(err)
	}
	var ports []int
	for _, r := range p.Plan.Routes {
		if r.Tor {
			ports = append(ports, r.ProxyPort)
		}
	}
	if len(ports) == 0 {
		t.Fatal("no Tor proxy port in the plan")
	}
	// another program takes the first port before shuntd
	squat, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(ports[0])))
	if err != nil {
		t.Skipf("port %d not free here: %v", ports[0], err)
	}
	defer squat.Close()
	var tp torProxy
	defer tp.Close()
	taken := tp.Update(p, func(string, string) func(context.Context, string, string) (net.Conn, error) { return nil })
	if !slices.Contains(taken, ports[0]) {
		t.Fatalf("taken port not reported: %v (ports %v)", taken, ports)
	}
	if _, ok := tp.runs[ports[0]]; ok {
		t.Fatal("a taken port must not count as running")
	}
	// the script that blocks it is valid nft and names the port
	if s := nft.TorGuardScript(taken); !strings.Contains(s, strconv.Itoa(ports[0])) || !strings.Contains(s, "drop") {
		t.Fatalf("guard script: %s", s)
	}
	if s := nft.TorGuardScript(nil); strings.Contains(s, "drop") {
		t.Fatalf("empty guard must only delete the table: %s", s)
	}
}

// M-04 for tunnel.socks: a SOCKS exit address another program holds is
// dropped by the guard table together with taken Tor ports.
func TestGuardScriptSocks(t *testing.T) {
	s := nft.GuardScript([]int{53001}, []netip.AddrPort{
		netip.MustParseAddrPort("127.0.0.1:1080"),
		netip.MustParseAddrPort("[::1]:1081"),
	})
	for _, want := range []string{
		"tcp dport { 53001 } drop",
		"ip daddr 127.0.0.1 tcp dport 1080 drop",
		"ip6 daddr ::1 tcp dport 1081 drop",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("guard script lacks %q:\n%s", want, s)
		}
	}
	if s := nft.GuardScript(nil, nil); strings.Contains(s, "drop") {
		t.Fatalf("empty guard must only delete the table: %s", s)
	}
	if s := nft.GuardScript(nil, []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:1080")}); strings.Contains(s, "53001") || !strings.Contains(s, "1080 drop") {
		t.Fatalf("socks-only guard: %s", s)
	}
}
