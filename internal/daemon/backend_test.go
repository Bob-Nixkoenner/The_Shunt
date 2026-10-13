package daemon

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/appwatch"
	"github.com/Bob-Nixkoenner/the_shunt/internal/dnsproxy"
	"github.com/Bob-Nixkoenner/the_shunt/internal/engine"
	"github.com/Bob-Nixkoenner/the_shunt/internal/firewall"
	"github.com/Bob-Nixkoenner/the_shunt/internal/tunnel"
)

// fakeBackend records what the daemon asks the platform to do.
type fakeBackend struct {
	mu      sync.Mutex
	procs   map[string][]int
	applied []map[string]engine.Group // held groups per Apply
	held    []map[string]engine.Group // per Hold
	routes  int
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
	return nil
}
func (f *fakeBackend) Panic(bool) error               { return nil }
func (f *fakeBackend) LiftLockdown() error            { return nil }
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
