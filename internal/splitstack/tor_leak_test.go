package splitstack

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/probe"
	"github.com/Bob-Nixkoenner/the_shunt/internal/socks"
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

// The leak test reaches the outside through Tor like the apps: the names go
// to Tor unresolved (Tor carries no UDP DNS), and Tor is confirmed.
func TestLeakProbeTorHandsNamesToTor(t *testing.T) {
	ipSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("203.0.113.9")) }))
	defer ipSrv.Close()
	torSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"IsTor":true,"IP":"203.0.113.9"}`))
	}))
	defer torSrv.Close()
	// names only the fake Tor knows: a lookup outside of it fails
	oi, ot := probe.IPURL, probe.TorURL
	probe.IPURL = "http://ip.tor-only.invalid:" + port(ipSrv.URL)
	probe.TorURL = "http://check.tor-only.invalid:" + port(torSrv.URL)
	defer func() { probe.IPURL, probe.TorURL = oi, ot }()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	asked := make(chan string, 4)
	srv := &socks.Server{Remote: true, Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		asked <- addr
		host, p, _ := net.SplitHostPort(addr)
		if !strings.HasSuffix(host, ".tor-only.invalid") {
			return nil, errors.New("unknown host")
		}
		return (&net.Dialer{}).DialContext(ctx, network, "127.0.0.1:"+p)
	}}
	go srv.Serve(l)

	e, _ := newTestEngine(t, map[string]any{
		"tunnels": []map[string]string{{"name": "tor", "type": "tor", "conf": "socks = " + l.Addr().String() + "\n"}},
		"default": "tunnel:tor",
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	b, err := e.ProbeRoute(ctx, "tunnel:tor")
	if err != nil {
		t.Fatal(err)
	}
	var r probe.Result
	json.Unmarshal(b, &r)
	if !r.Tor || !r.IsTor || r.IP != "203.0.113.9" {
		t.Errorf("probe through Tor: %+v", r)
	}
	select {
	case a := <-asked:
		if !strings.Contains(a, "tor-only.invalid") {
			t.Errorf("Tor was asked for %q, not the name", a)
		}
	default:
		t.Error("nothing went through Tor")
	}
}

func port(u string) string { return u[strings.LastIndex(u, ":")+1:] }
