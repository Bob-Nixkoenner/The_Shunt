package desktopapp

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/api"
	"github.com/Bob-Nixkoenner/the_shunt/internal/defense"
	"github.com/Bob-Nixkoenner/the_shunt/internal/tunnel"
)

func status(panic bool, hsAgo time.Duration, now time.Time) *api.Status {
	return &api.Status{DefaultRoute: "direct", Panic: panic, Tunnels: []api.TunnelStatus{{
		Name: "vps", Up: true, Peers: []tunnel.PeerStatus{{LastHandshake: now.Add(-hsAgo), KeepaliveSec: 25}},
	}}}
}

func TestCompute(t *testing.T) {
	now := time.Now()
	if v := Compute(status(false, 30*time.Second, now), nil, now); v.Level != OK || len(v.Down) != 0 {
		t.Errorf("fresh handshake: %+v", v)
	}
	if v := Compute(status(false, 10*time.Minute, now), nil, now); v.Level != Warn || !v.Down["vps"] {
		t.Errorf("stale handshake: %+v", v)
	}
	idle := status(false, 10*time.Minute, now)
	idle.Tunnels[0].Peers[0].KeepaliveSec = 0
	if v := Compute(idle, nil, now); v.Level != OK {
		t.Errorf("idle tunnel without keepalive is not broken: %+v", v)
	}
	if v := Compute(status(false, 30*time.Second, now), nil, now); v.Active != 1 {
		t.Errorf("one connected tunnel counts as active: %+v", v)
	}
	if v := Compute(status(false, 10*time.Minute, now), nil, now); v.Active != 0 {
		t.Errorf("a tunnel without connection is not active: %+v", v)
	}
	if v := Compute(idle, nil, now); v.Active != 1 {
		t.Errorf("an idle on-demand tunnel counts as active: %+v", v)
	}
	if v := Compute(status(true, time.Second, now), nil, now); v.Level != Bad || !v.Panic {
		t.Errorf("panic: %+v", v)
	}
	if v := Compute(nil, errors.New("x"), now); v.Level != Bad {
		t.Errorf("unreachable: %+v", v)
	}
}

func TestDiff(t *testing.T) {
	now := time.Now()
	ok := Compute(status(false, time.Second, now), nil, now)
	down := Compute(status(false, time.Hour, now), nil, now)
	gone := Compute(nil, errors.New("x"), now)
	panic := Compute(status(true, time.Second, now), nil, now)
	cases := []struct {
		name      string
		prev, cur View
		want      int
	}{
		{"steady", ok, ok, 0},
		{"tunnel lost", ok, down, 1},
		{"tunnel back", down, ok, 1},
		{"daemon gone", ok, gone, 1},
		{"daemon back", gone, ok, 1},
		{"panic on", ok, panic, 1},
		{"panic off", panic, ok, 1},
	}
	for _, c := range cases {
		if got := Diff(c.prev, c.cur, false); len(got) != c.want {
			t.Errorf("%s: %d notifications %+v", c.name, len(got), got)
		}
	}
	if got := Diff(View{}, gone, true); len(got) != 1 {
		t.Errorf("first view unreachable: %+v", got)
	}
	if got := Diff(View{}, ok, true); len(got) != 0 {
		t.Errorf("first view ok: %+v", got)
	}
}

func TestIconsDiffer(t *testing.T) {
	a, b, c := Icon(OK), Icon(Warn), Icon(Bad)
	if len(a) < 200 || string(a) == string(b) || string(b) == string(c) {
		t.Fatal("icons missing or identical")
	}
}

func TestIconBadge(t *testing.T) {
	plain, one, two, many := IconN(OK, 0), IconN(OK, 1), IconN(OK, 2), IconN(OK, 40)
	if string(plain) != string(Icon(OK)) || string(plain) == string(one) || string(one) == string(two) {
		t.Fatal("the badge must show for active tunnels, and change with the number")
	}
	if string(many) != string(IconN(OK, 9)) {
		t.Fatal("more than 9 show 9")
	}
}

func TestAutostart(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if AutostartEnabled() {
		t.Fatal("enabled before")
	}
	if err := SetAutostart(true, "/usr/local/bin/shunt-desktop"); err != nil || !AutostartEnabled() {
		t.Fatal("enable failed", err)
	}
	if err := SetAutostart(false, ""); err != nil || AutostartEnabled() {
		t.Fatal("disable failed", err)
	}
}

func TestSingleInstance(t *testing.T) {
	name := fmt.Sprintf("@the-shunt-desktop-test-%d-%d", os.Getuid(), os.Getpid())
	old := socketName
	socketName = func() string { return name }
	t.Cleanup(func() { socketName = old })
	s, err := Claim()
	if err != nil || s == nil {
		t.Fatalf("first claim: %v", err)
	}
	shown := make(chan bool, 1)
	go s.Requests(func() { shown <- true })
	s2, err := Claim()
	if err != nil || s2 != nil {
		t.Fatalf("second claim should defer to the first: %v %v", s2, err)
	}
	select {
	case <-shown:
	case <-time.After(2 * time.Second):
		t.Fatal("first instance was not asked to show")
	}
}

// SHUNT_ICON_DIR=/tmp/x go test -run WriteIcons: dump the icons to look at them
func TestWriteIcons(t *testing.T) {
	dir := os.Getenv("SHUNT_ICON_DIR")
	if dir == "" {
		t.Skip()
	}
	for i, l := range []Level{OK, Warn, Bad} {
		_ = os.WriteFile(filepath.Join(dir, fmt.Sprintf("icon%d.png", i)), Icon(l), 0o644)
	}
}

func TestCaptive(t *testing.T) {
	now := time.Now()
	st := &api.Status{DefaultRoute: "tunnel:vps", Captive: "portal"}
	v := Compute(st, nil, now)
	if v.Level != Warn || !v.Captive {
		t.Fatalf("%+v", v)
	}
	n := Diff(View{Down: map[string]bool{}, DNSDown: map[string]bool{}}, v, false)
	if len(n) != 1 || n[0].Summary != "Wi-Fi login needed" {
		t.Errorf("%+v", n)
	}
	st.Captive = "online"
	if n := Diff(v, Compute(st, nil, now), false); len(n) != 1 || n[0].Summary != "Wi-Fi login done" {
		t.Errorf("%+v", n)
	}
}

func TestPending(t *testing.T) {
	now := time.Now()
	v := Compute(&api.Status{DefaultRoute: "direct", Pending: 2}, nil, now)
	if v.Level != Warn || v.Pending != 2 {
		t.Fatalf("%+v", v)
	}
	n := Diff(View{Down: map[string]bool{}, DNSDown: map[string]bool{}}, v, false)
	if len(n) != 1 || n[0].Summary != "An app wants to go online" {
		t.Errorf("%+v", n)
	}
}

func defView(heat int) View {
	now := time.Now()
	st := status(false, time.Second, now)
	if heat >= 0 {
		st.Defense = &api.DefenseBrief{Heat: heat, Level: defense.LevelFor(heat), Class: defense.ClassUnknown}
	}
	return Compute(st, nil, now)
}

func TestDefenseNotifications(t *testing.T) {
	if v := defView(63); v.DefHeat != 63 || v.DefLevel != defense.LevelHot {
		t.Fatalf("view carries heat and level: %+v", v)
	}
	if v := defView(-1); v.DefLevel != "" {
		t.Fatalf("defense off: %+v", v)
	}
	cases := []struct {
		name       string
		prev, cur  int
		want       int
		wantUrgent bool
	}{
		{"quiet stays", 5, 10, 0, false},
		{"quiet to noticed", 10, 30, 1, false},
		{"noticed to hot", 30, 55, 1, false},
		{"hot to attack is urgent", 55, 90, 1, true},
		{"quiet to attack at once", 5, 95, 1, true},
		{"same level, heat rises", 52, 70, 0, false},
		{"falling is not reported", 90, 40, 0, false},
		{"falling to quiet", 40, 5, 0, false},
		{"off to noticed", -1, 30, 1, false},
		{"off to quiet", -1, 5, 0, false},
	}
	for _, c := range cases {
		got := Diff(defView(c.prev), defView(c.cur), false)
		if len(got) != c.want {
			t.Errorf("%s: %d notifications %+v", c.name, len(got), got)
			continue
		}
		if c.want == 1 && got[0].Urgent != c.wantUrgent {
			t.Errorf("%s: urgent = %v", c.name, got[0].Urgent)
		}
	}
	if got := Diff(View{}, defView(90), true); len(got) != 0 {
		t.Errorf("first view is not announced: %+v", got)
	}
}

func TestExposedNotification(t *testing.T) {
	mk := func(exposed bool, inbound string) View {
		now := time.Now()
		st := status(false, time.Second, now)
		st.Defense = &api.DefenseBrief{Heat: 5, Level: defense.LevelQuiet, Class: defense.ClassSafe, Exposed: exposed, ExposedInbound: inbound}
		return Compute(st, nil, now)
	}
	if n := Diff(mk(false, ""), mk(true, "closed"), false); len(n) != 1 || n[0].Urgent || n[0].Summary != "Directly reachable from the internet" {
		t.Fatalf("closed: %+v", n)
	}
	if n := Diff(mk(false, ""), mk(true, "open"), false); len(n) != 1 || !n[0].Urgent {
		t.Fatalf("open must be urgent: %+v", n)
	}
	if n := Diff(mk(true, "open"), mk(true, "open"), false); len(n) != 0 {
		t.Fatalf("no repeat: %+v", n)
	}
}
