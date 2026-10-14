package daemon

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/appwatch"
	"github.com/Bob-Nixkoenner/the_shunt/internal/dnsproxy"
	"github.com/Bob-Nixkoenner/the_shunt/internal/engine"
	"github.com/Bob-Nixkoenner/the_shunt/internal/firewall"
	"github.com/Bob-Nixkoenner/the_shunt/internal/netdetect"
	"github.com/Bob-Nixkoenner/the_shunt/internal/routing"
	"github.com/Bob-Nixkoenner/the_shunt/internal/tunnel"
)

// fakeBackend records what the daemon asks the platform to do.
type fakeBackend struct {
	mu      sync.Mutex
	procs   map[string][]int
	applied []map[string]engine.Group // held groups per Apply
	held    []map[string]engine.Group // per Hold
	routes  int
	syncErr error // returned by SyncRoutes
}

func newFake() *fakeBackend { return &fakeBackend{procs: map[string][]int{}} }

func (f *fakeBackend) Init() (string, error)               { return "shunt", nil }
func (f *fakeBackend) Groups() firewall.CGroups            { return fakeGroups{f} }
func (f *fakeBackend) Render(*engine.Plan) (string, error) { return "ruleset", nil }
func (f *fakeBackend) Apply(_ string, held map[string]engine.Group) error {
	f.applied = append(f.applied, held)
	return nil
}
func (f *fakeBackend) Hold(held map[string]engine.Group) error {
	f.held = append(f.held, held)
	return nil
}
func (f *fakeBackend) WatchHeld(context.Context, func(string, int)) error { return nil }
func (f *fakeBackend) SyncRoutes(*engine.Plan, map[string]bool) error {
	f.routes++
	return f.syncErr
}
func (f *fakeBackend) Panic(bool) error               { return nil }
func (f *fakeBackend) ForgetTCP(uint32) (int, error)  { return 0, nil }
func (f *fakeBackend) LiftLockdown() error            { return nil }
func (f *fakeBackend) Stopped(*engine.Plan) error     { return nil }
func (f *fakeBackend) Cleanup() error                 { return nil }
func (f *fakeBackend) DomainSets() dnsproxy.SetWriter { return nil }
func (f *fakeBackend) CgroupOf(int) (string, bool)    { return "", false }
func (f *fakeBackend) Comm(int) (string, bool)        { return "", false }
func (f *fakeBackend) Pids() []int                    { return nil }
func (f *fakeBackend) Watcher(*slog.Logger, func(int, appwatch.Proc)) AppWatcher {
	return fakeWatcher{}
}

type fakeGroups struct{ f *fakeBackend }

func (g fakeGroups) Ensure(string) error { return nil }
func (g fakeGroups) Remove(rel string) error {
	delete(g.f.procs, rel)
	return nil
}
func (g fakeGroups) Procs(rel string) ([]int, error) { return g.f.procs[rel], nil }
func (g fakeGroups) Move(rel string, pid int) error {
	g.f.procs[rel] = append(g.f.procs[rel], pid)
	return nil
}

type fakeWatcher struct{}

func (fakeWatcher) SetTargets([]appwatch.Target, string) {}
func (fakeWatcher) SetRecheck(string)                    {}
func (fakeWatcher) Place(int, string)                    {}
func (fakeWatcher) Run(<-chan struct{})                  {}

func testDaemon(t *testing.T, conf string) (*Daemon, *fakeBackend) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "shunt.toml")
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	f := newFake()
	d := &Daemon{ConfigPath: path, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Backend: f}
	d.cg = f.Groups()
	d.tunnels, d.specHash, d.tunErrors = map[string]tunnel.Device{}, map[string]string{}, map[string]string{}
	return d, f
}

// A reload replaces the platform's rules: the app firewall's held groups
// must be part of the very same Apply, or held programs get out between.
func TestReloadKeepsHeldGroups(t *testing.T) {
	d, f := testDaemon(t, "[daemon]\nsocket = \"/nonexistent/s.sock\"\n[dns]\ndisabled = true\n[firewall]\nmode = \"block\"\n")
	if err := d.reload("shunt"); err != nil {
		t.Fatal(err)
	}
	d.fw.Unknown(4242, appwatch.Proc{Comm: "curl", Exe: "/usr/bin/curl", UID: 1000,
		Cgroup: "user.slice/user-1000.slice/user@1000.service/app.slice/app-x.scope"})
	if len(f.held) == 0 || f.held[len(f.held)-1]["p1"].Path != "shunt/apps/ask/p1" {
		t.Fatalf("not held: %v", f.held)
	}
	if err := d.reload("shunt"); err != nil {
		t.Fatal(err)
	}
	if got := f.applied[len(f.applied)-1]["p1"].Path; got != "shunt/apps/ask/p1" {
		t.Fatalf("reload applied the ruleset without the held group: %v", f.applied)
	}
	if f.routes == 0 {
		t.Error("routes never synced")
	}
}

// A network profile can switch the direct DNS: home Pi-hole, the
// network's own resolvers, or keep dns.direct.
func TestNetworkDNSDirect(t *testing.T) {
	conf := `[daemon]
socket = "/nonexistent/s.sock"
[dns]
direct = "cloudflare"
[dns.upstream.cloudflare]
addr = "1.1.1.1"
[dns.upstream.pihole]
addr = "192.168.1.2"
[[network]]
name = "home"
ssid = ["home"]
default_route = "direct"
dns_direct = "pihole"
[[network]]
name = "guest"
ssid = ["guest"]
default_route = "direct"
dns_direct = "system"
[[network]]
name = "work"
ssid = ["work"]
default_route = "direct"
`
	path := filepath.Join(t.TempDir(), "shunt.toml")
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	for ssid, want := range map[string]string{"home": "192.168.1.2:53", "guest": "system", "work": "1.1.1.1:53", "elsewhere": "1.1.1.1:53"} {
		p, err := PrepareOn(path, "shunt", Env{Net: &netdetect.Info{SSID: ssid}, Backend: newFake()})
		if err != nil {
			t.Fatal(err)
		}
		got := "system"
		if ups := p.DNSUpstreams["direct"]; len(ups) > 0 {
			got = ups[0].Addr.String()
		} else if !p.DirectSystem {
			got = "none"
		}
		if got != want {
			t.Errorf("%s: direct DNS %s, want %s", ssid, got, want)
		}
	}
	if err := os.WriteFile(path, []byte(conf+"[[network]]\nname = \"x\"\nssid = [\"x\"]\ndefault_route = \"direct\"\ndns_direct = \"nope\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareOn(path, "shunt", Env{Backend: newFake()}); err == nil {
		t.Error("unknown dns_direct accepted")
	}
}

// A switched-off tunnel stays in the config but is never started; its
// route blocks (no interface: only the kill switch route).
func TestDisabledTunnelNotStarted(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	d, _ := testDaemon(t, "[daemon]\nsocket = \"/nonexistent/s.sock\"\n[dns]\ndisabled = true\n[tunnel.vpn]\nconfig = \"vpn.conf\"\ndisabled = true\n")
	wg := "[Interface]\nPrivateKey = " + key + "\nAddress = 10.9.0.2/32\n[Peer]\nPublicKey = " + key + "\nEndpoint = 192.0.2.1:51820\nAllowedIPs = 0.0.0.0/0\n"
	if err := os.WriteFile(filepath.Join(filepath.Dir(d.ConfigPath), "vpn.conf"), []byte(wg), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := d.reload("shunt"); err != nil {
		t.Fatal(err)
	}
	if len(d.tunnels) != 0 || len(d.tunErrors) != 0 {
		t.Fatalf("switched-off tunnel was started: %v %v", d.tunnels, d.tunErrors)
	}
	st := d.status()
	if len(st.Tunnels) != 1 || !st.Tunnels[0].Disabled || st.Tunnels[0].Up {
		t.Fatalf("status: %+v", st.Tunnels)
	}
}

// A route that can't be copied yet (cable just plugged in) must not fail
// a config save; a real routing error still does.
func TestSoftRouteErrorsDontFailReload(t *testing.T) {
	d, f := testDaemon(t, "[daemon]\nsocket = \"/nonexistent/s.sock\"\n[dns]\ndisabled = true\n")
	f.syncErr = errors.Join(&routing.SoftError{Err: errors.New("table 5525 route 0.0.0.0/0: network is unreachable")})
	if err := d.reload("shunt"); err != nil {
		t.Fatalf("soft error failed the reload: %v", err)
	}
	if d.routeSoft == "" {
		t.Error("soft error not remembered for the retry")
	}
	f.syncErr = errors.New("table 5301: no unreachable route")
	if err := d.reload("shunt"); err == nil {
		t.Error("hard routing error accepted")
	}
}

// During a pass every route is direct: default, network profile and rules
// (block too); without it the config applies as written.
func TestPassPlan(t *testing.T) {
	conf := `[daemon]
socket = "/nonexistent/s.sock"
default_route = "block"
[[rule]]
name = "ssh blocked"
port = ["tcp/22"]
route = "block"
[[network]]
name = "cafe"
ssid = ["cafe"]
default_route = "block"
`
	path := filepath.Join(t.TempDir(), "shunt.toml")
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, pass := range []bool{false, true} {
		p, err := PrepareOn(path, "shunt", Env{Net: &netdetect.Info{SSID: "cafe"}, Backend: newFake(), Pass: pass})
		if err != nil {
			t.Fatal(err)
		}
		want := "block"
		if pass {
			want = "direct"
		}
		if got := p.Plan.DefaultRoute.String(); got != want {
			t.Errorf("pass=%v: default route %s, want %s", pass, got, want)
		}
		for _, r := range p.Plan.Rules {
			if r.Name == "ssh blocked" && r.Route.String() != want {
				t.Errorf("pass=%v: rule route %s, want %s", pass, r.Route, want)
			}
		}
		if pass && (len(p.Warnings) == 0 || !strings.Contains(strings.Join(p.Warnings, " "), "pass")) {
			t.Error("no warning during a pass")
		}
	}
}
