package firewall

import (
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/appwatch"
	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/Bob-Nixkoenner/the_shunt/internal/engine"
)

type fakeCG struct{ procs map[string][]int }

func (f *fakeCG) Ensure(rel string) error { return nil }
func (f *fakeCG) Remove(rel string) error { delete(f.procs, rel); return nil }
func (f *fakeCG) Procs(rel string) ([]int, error) {
	return f.procs[rel], nil
}
func (f *fakeCG) Move(rel string, pid int) error {
	for g, ps := range f.procs {
		for i, p := range ps {
			if p == pid {
				f.procs[g] = append(ps[:i:i], ps[i+1:]...)
			}
		}
	}
	f.procs[rel] = append(f.procs[rel], pid)
	return nil
}
func (f *fakeCG) where(pid int) string {
	for g, ps := range f.procs {
		for _, p := range ps {
			if p == pid {
				return g
			}
		}
	}
	return ""
}

const app = "user.slice/user-1000.slice/user@1000.service/app.slice/app-firefox-1.scope"

func newMgr(t *testing.T, mode string) (*Manager, *fakeCG, *[]map[string]engine.Group) {
	cg := &fakeCG{procs: map[string][]int{}}
	var rules []map[string]engine.Group
	m := &Manager{Log: slog.New(slog.NewTextHandler(io.Discard, nil)), CG: cg, Store: filepath.Join(t.TempDir(), "apps.json"),
		Hold: func(h map[string]engine.Group) error { rules = append(rules, h); return nil }}
	err := m.Configure(Settings{Mode: mode, Timeout: 30 * time.Second, Root: "shunt",
		Groups: map[string]string{"tunnel:vps": "shunt/apps/via/tunnel-vps", "direct": "shunt/apps/via/direct"}})
	if err != nil {
		t.Fatal(err)
	}
	return m, cg, &rules
}

func TestHoldAskDecide(t *testing.T) {
	m, cg, rules := newMgr(t, config.FirewallAsk)
	ff := appwatch.Proc{Comm: "firefox", Exe: "/usr/lib/firefox/firefox", Cgroup: app, UID: 1000}
	m.Unknown(100, ff)
	m.Unknown(101, ff) // second process of the same program: same group
	if cg.where(100) != "shunt/apps/ask/p1" || cg.where(101) != "shunt/apps/ask/p1" {
		t.Fatalf("not held: %v", cg.procs)
	}
	if g := (*rules)[len(*rules)-1]["p1"]; g.Path != "shunt/apps/ask/p1" {
		t.Errorf("not blocked: %v", (*rules)[len(*rules)-1])
	}
	if len(m.List()) != 0 {
		t.Error("listed before it used the network")
	}
	m.Seen("p1", 1000)
	l := m.List()
	if len(l) != 1 || l[0].Name != "firefox" || l[0].Procs != 2 || l[0].Deadline.IsZero() {
		t.Fatalf("%+v", l)
	}
	if err := m.Decide("p1", "tunnel:vps", true); err != nil {
		t.Fatal(err)
	}
	if cg.where(100) != "shunt/apps/via/tunnel-vps" || len(m.List()) != 0 {
		t.Errorf("not moved: %v", cg.procs)
	}
	m.Unknown(102, ff) // next start: no question
	if cg.where(102) != "shunt/apps/via/tunnel-vps" {
		t.Errorf("not remembered: %v", cg.procs)
	}
	// stored decision survives a restart
	m2 := &Manager{Log: m.Log, CG: cg, Store: m.Store}
	_ = m2.Configure(m.set)
	if r := m2.Remembered(); len(r) != 1 || r[0].Route != "tunnel:vps" {
		t.Errorf("%+v", r)
	}
}

func TestTimeoutAndScope(t *testing.T) {
	m, cg, _ := newMgr(t, config.FirewallAsk)
	m.Unknown(200, appwatch.Proc{Comm: "curl", Exe: "/usr/bin/curl", Cgroup: app, TTY: true})
	m.Unknown(201, appwatch.Proc{Comm: "NetworkManager", Exe: "/usr/sbin/NetworkManager", Cgroup: "system.slice/NetworkManager.service"})
	m.Unknown(202, appwatch.Proc{Comm: "cosmic-panel", Exe: "/usr/bin/cosmic-panel", Cgroup: app})
	if len(cg.procs) != 0 {
		t.Fatalf("held what must not be held: %v", cg.procs)
	}
	m.Unknown(203, appwatch.Proc{Comm: "thunderbird", Exe: "/usr/bin/thunderbird", Cgroup: "user.slice/user-1000.slice/session-2.scope"})
	m.Seen("p1", -1)
	m.Tick(time.Now().Add(31 * time.Second))
	if cg.where(203) != "shunt/apps/free" || len(m.List()) != 0 {
		t.Errorf("timeout: %v", cg.procs)
	}
}

func TestBlockNoTimeoutAndOff(t *testing.T) {
	m, cg, _ := newMgr(t, config.FirewallBlock)
	m.Unknown(300, appwatch.Proc{Comm: "spotify", Exe: "/opt/spotify/spotify", Cgroup: app})
	m.Seen("p1", 1000)
	m.Tick(time.Now().Add(time.Hour))
	if cg.where(300) != "shunt/apps/ask/p1" {
		t.Fatalf("block mode released: %v", cg.procs)
	}
	_ = m.Configure(Settings{Mode: config.FirewallOff, Root: "shunt"})
	if cg.where(300) != "shunt/apps/free" {
		t.Errorf("off did not release: %v", cg.procs)
	}
}

func TestFlatpakKey(t *testing.T) {
	k, n := keyOf(appwatch.Proc{Comm: "signal-desktop", Cgroup: "user.slice/user-1000.slice/user@1000.service/app.slice/app-flatpak-org.signal.Signal-12345.scope"})
	if k != "flatpak:org.signal.Signal" || n != "org.signal.Signal" {
		t.Errorf("%s %s", k, n)
	}
}

func TestWrapperExecGetsOwnDecision(t *testing.T) {
	m, cg, _ := newMgr(t, config.FirewallAsk)
	m.Unknown(400, appwatch.Proc{Comm: "brave-browser", Exe: "/usr/bin/bash", Cgroup: app})
	held := cg.where(400)
	m.Unknown(400, appwatch.Proc{Comm: "brave", Exe: "/opt/brave.com/brave/brave", Cgroup: held}) // exec
	if cg.where(400) == held || cg.where(400) == "" {
		t.Fatalf("exec'd program stayed in the wrapper's group: %v", cg.procs)
	}
	m.Seen("p2", 1000)
	if l := m.List(); len(l) != 1 || l[0].Name != "brave" {
		t.Errorf("%+v", l)
	}
}

// A ruleset reload replaces the table: the held groups must come with the
// new ruleset (new root included), not after it.
func TestHeldForReload(t *testing.T) {
	m, _, _ := newMgr(t, config.FirewallBlock)
	m.Unknown(100, appwatch.Proc{Comm: "curl", Exe: "/usr/bin/curl", Cgroup: app, UID: 1000})
	if g := m.HeldFor("newroot")["p1"]; g.Path != "newroot/apps/ask/p1" {
		t.Errorf("held group missing: %v", m.HeldFor("newroot"))
	}
}

// A held program that ends without ever going online: its group and its
// block rule both go.
func TestUnaskedGoneDropsRule(t *testing.T) {
	m, cg, rules := newMgr(t, config.FirewallAsk)
	m.Unknown(100, appwatch.Proc{Comm: "sleep", Exe: "/usr/bin/sleep", Cgroup: app, UID: 1000})
	if _, ok := (*rules)[len(*rules)-1]["p1"]; !ok {
		t.Fatal("not held")
	}
	delete(cg.procs, "shunt/apps/ask/p1") // the program ended
	m.Tick(time.Now())
	if g, ok := (*rules)[len(*rules)-1]["p1"]; ok {
		t.Fatalf("block rule of a gone program left behind: %v", g)
	}
}
