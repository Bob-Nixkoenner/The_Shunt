package splitstack

import (
	"context"
	"encoding/json"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/probe"
)

func torEngine(t *testing.T, exe string) *Engine {
	t.Helper()
	e, _ := newTestEngine(t, map[string]any{
		"tunnels":   []map[string]string{{"name": "tor", "type": "tor", "conf": "client = builtin\n"}},
		"default":   "tunnel:tor",
		"on_demand": true, // Tor must not sleep even so
		"tor_exe":   exe,
		"work_dir":  t.TempDir(),
	})
	return e
}

func leakRows(t *testing.T, e *Engine) map[string]probe.RouteResult {
	t.Helper()
	var rs []probe.RouteResult
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := json.Unmarshal([]byte(e.LeakTest(ctx)), &rs); err != nil {
		t.Fatal(err)
	}
	m := map[string]probe.RouteResult{}
	for _, r := range rs {
		m[r.Route] = r
	}
	return m
}

// A Tor tunnel never sleeps on demand: its program starts with the engine.
func TestTorNeverSleeps(t *testing.T) {
	t.Setenv("TOR_FAKE", "1")
	exe, _ := os.Executable()
	e := torEngine(t, exe)
	if up, idle := tunnelState(e, "tor"); idle {
		t.Errorf("tor tunnel asleep: up %v idle %v", up, idle)
	}
	if onDemandEligible(tunnelConf{Name: "tor", Type: typeTor}, nil) {
		t.Error("tor tunnel is eligible for sleep")
	}
}

// The leak test waits for a Tor that is still starting instead of calling it "blocked".
func TestLeakTestWaitsForTor(t *testing.T) {
	t.Setenv("TOR_FAKE", "1")
	exe, _ := os.Executable()
	oldMax, oldPoll := torWaitMax, torPoll
	torWaitMax, torPoll = 20*time.Second, 50*time.Millisecond
	defer func() { torWaitMax, torPoll = oldMax, oldPoll }()
	oldLim := torProbeLimit
	torProbeLimit = time.Second
	defer func() { torProbeLimit = oldLim }()
	e := torEngine(t, exe)
	start := time.Now()
	r, ok := leakRows(t, e)["tunnel:tor"]
	if !ok {
		t.Fatal("no row for the tor tunnel")
	}
	if r.Verdict == "starting" || r.Verdict == "error" && r.Note == "Tor does not start" {
		t.Errorf("did not wait: %+v", r)
	}
	if tt := e.tunnel("tor").tor; tt.proc.Bootstrap() != 100 {
		t.Errorf("probed at %d %%", tt.proc.Bootstrap())
	}
	if time.Since(start) < time.Second {
		t.Errorf("returned after %s, before the fake tor was through", time.Since(start))
	}
	// the card is healthy once Tor is through
	var st struct{ Tunnels []tunnelStatus }
	json.Unmarshal([]byte(e.Status()), &st)
	if len(st.Tunnels) != 1 || !st.Tunnels[0].Up || st.Tunnels[0].Health.State != "ok" {
		t.Errorf("status: %+v", st.Tunnels)
	}
}

// If Tor does not get through in time the row says "starting" with its progress.
func TestLeakTestTorStillStarting(t *testing.T) {
	t.Setenv("TOR_FAKE", "1")
	exe, _ := os.Executable()
	oldMax, oldPoll := torWaitMax, torPoll
	torWaitMax, torPoll = 100*time.Millisecond, 20*time.Millisecond
	defer func() { torWaitMax, torPoll = oldMax, oldPoll }()
	e := torEngine(t, exe)
	time.Sleep(1300 * time.Millisecond) // the control port is polled each second: 40 % until 1.5 s
	r := leakRows(t, e)["tunnel:tor"]
	if r.Verdict != "starting" || r.Progress <= 0 || r.Progress >= 100 || !strings.Contains(r.Note, "still starting") {
		t.Errorf("row: %+v", r)
	}
}

// A tor that dies on the spot shows why (exit code, last line), also in the leak test.
func TestTorFailureIsVisible(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs /bin/sh")
	}
	oldMax, oldPoll := torWaitMax, torPoll
	torWaitMax, torPoll = 300*time.Millisecond, 20*time.Millisecond
	defer func() { torWaitMax, torPoll = oldMax, oldPoll }()
	sh := t.TempDir() + "/tor"
	os.WriteFile(sh, []byte("#!/bin/sh\necho 'Could not open DataDirectory' >&2\nexit 3\n"), 0o755)
	e := torEngine(t, sh)
	deadline := time.Now().Add(5 * time.Second)
	var st tunnelStatus
	for time.Now().Before(deadline) {
		st = e.tunnel("tor").status()
		if strings.Contains(st.Error, "Tor failed") {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !strings.Contains(st.Error, "exit status 3") || !strings.Contains(st.Error, "Could not open DataDirectory") || st.Up {
		t.Errorf("status: %+v", st)
	}
	r := leakRows(t, e)["tunnel:tor"]
	if r.Verdict != "error" || r.Note != "Tor does not start" || !strings.Contains(r.Detail, "exit status 3") {
		t.Errorf("row: %+v", r)
	}
	if msg := e.TorStart("tor"); msg != "" {
		t.Errorf("TorStart: %q", msg)
	}
	// a tor that cannot be executed at all
	e2 := torEngine(t, "/nonexistent/libtor.so")
	time.Sleep(200 * time.Millisecond)
	if st := e2.tunnel("tor").status(); !strings.Contains(st.Error, "no such file") {
		t.Errorf("exec error not shown: %+v", st)
	}
}
