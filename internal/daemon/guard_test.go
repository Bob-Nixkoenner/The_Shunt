package daemon

import (
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/Bob-Nixkoenner/the_shunt/internal/engine"
	"github.com/Bob-Nixkoenner/the_shunt/internal/socks"
)

func guardPlan(t *testing.T) (*config.Config, *engine.Plan) {
	t.Helper()
	c, err := config.Parse(`
[daemon]
default_route = "tunnel:vps"
[tunnel.vps]
config = "vps.conf"
socks = "127.0.0.1:1080"
socks_users = ["1000", "someone"]
[tunnel.home]
config = "home.conf"
socks = "[::1]:1081"
`)
	if err != nil {
		t.Fatal(err)
	}
	all := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	p, err := engine.Compile(c, "shunt", map[string]engine.TunnelInfo{
		"vps":  {Iface: "sh-vps", HasV4: true, AllowedIPs: all, Addrs: []netip.Addr{netip.MustParseAddr("10.166.0.12")}},
		"home": {Iface: "sh-home", HasV4: true, AllowedIPs: all, Addrs: []netip.Addr{netip.MustParseAddr("10.9.0.2")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return c, p
}

// With shuntd stopped every loopback port of its listeners is closed: the
// DNS listener ports, the Tor proxy ports and the SOCKS exits.
func TestStoppedGuard(t *testing.T) {
	c, p := guardPlan(t)
	r := p.RouteByName("tunnel:home")
	r.Tor, r.ProxyPort = true, 53001 // as a Tor route would have it
	g := stoppedGuard(c, p)
	if !slices.Equal(g.TorPorts, []int{53001}) {
		t.Errorf("tor ports %v", g.TorPorts)
	}
	want := []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:1080"), netip.MustParseAddrPort("[::1]:1081")}
	if !slices.Equal(g.Socks, want) {
		t.Errorf("socks %v, want %v", g.Socks, want)
	}
	if !p.DNS || len(g.DNSPorts) == 0 {
		t.Fatalf("dns ports %v (plan DNS %v)", g.DNSPorts, p.DNS)
	}
	for _, r := range p.Routes {
		if r.DNSPort > 0 && !slices.Contains(g.DNSPorts, r.DNSPort) {
			t.Errorf("listener port %d of %s stays open", r.DNSPort, r)
		}
	}
	if len(g.Exits) != 0 {
		t.Error("no exit runs while shuntd is stopped")
	}
}

type guardFake struct {
	*fakeBackend
	guards []LoopbackGuard
}

func (g *guardFake) GuardLoopback(lg LoopbackGuard) error {
	g.guards = append(g.guards, lg)
	return nil
}

func TestShutdownSetsStoppedGuard(t *testing.T) {
	c, p := guardPlan(t)
	f := &guardFake{fakeBackend: newFake()}
	d := &Daemon{Backend: f, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), cfg: c, plan: p}
	d.shutdown()
	if len(f.guards) != 1 || len(f.guards[0].Socks) != 2 || len(f.guards[0].DNSPorts) == 0 {
		t.Fatalf("guards set on shutdown: %+v", f.guards)
	}
}

// M-06: only running exits get a guard; socks_users resolve to UIDs, and a
// name that does not resolve is left out (closed to it), never ignored.
func TestExitUsers(t *testing.T) {
	c, _ := guardPlan(t)
	old := lookupUID
	defer func() { lookupUID = old }()
	lookupUID = func(name string) (uint32, error) {
		if name == "1000" {
			return 1000, nil
		}
		return 0, errors.New("unknown user")
	}
	d := &Daemon{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	got := d.exitUsers(c, map[string]string{"vps": socks.StateListening, "home": socks.StateTaken})
	if len(got) != 1 {
		t.Fatalf("exits %+v, want only the running one", got)
	}
	e := got[0]
	if e.Addr != netip.MustParseAddrPort("127.0.0.1:1080") || !e.Users || !slices.Equal(e.UIDs, []uint32{1000}) {
		t.Fatalf("exit %+v", e)
	}
	got = d.exitUsers(c, map[string]string{"home": socks.StateListening})
	if len(got) != 1 || got[0].Users {
		t.Fatalf("exit without socks_users: %+v", got)
	}
}
