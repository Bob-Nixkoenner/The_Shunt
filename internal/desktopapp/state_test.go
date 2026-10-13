package desktopapp

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/api"
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
