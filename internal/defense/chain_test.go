package defense

import (
	"bufio"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func chainManager(t *testing.T, block bool) (*Manager, *fakeClock, chan Ban) {
	t.Helper()
	pm := &portMap{real: map[int]int{}}
	banCh := make(chan Ban, 8)
	m, clk := newTestManager(t, pm, banCh)
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.DecoyPorts = nil
	cfg.Features[FeatBrute] = Feature{Watch: true, Block: block}
	cfg.Ignore = []IgnoreEntry{{Addr: "198.51.100.0/24", Name: "own device"}}
	m.Configure(cfg)
	m.SetNetwork("k", ClassUnknown)
	return m, clk, banCh
}

// steps: s = scan finding, c = decoy handshake, l = ssh login try; each with
// the time since the previous step.
type chainStep struct {
	what  byte
	after time.Duration
}

func runChain(m *Manager, clk *fakeClock, src string, steps []chainStep) {
	a := netip.MustParseAddr(src)
	for _, s := range steps {
		clk.Add(s.after)
		switch s.what {
		case 's':
			m.Report(Event{Kind: KindScan, Severity: SevHigh, Src: src, Detail: "mode=many_ports distinct ports in window: 6"})
		case 'c':
			m.decoyHit(Hit{Src: a, Port: 22, Kind: KindDecoyHit, Sev: SevMedium, Detail: "tcp connect"})
		case 'l':
			m.decoyHit(Hit{Src: a, Port: 22, Kind: KindCowrie, Sev: SevMedium, Detail: "ssh login user=root len=6 h=00000000 client=SSH-2.0-x"})
		}
	}
}

func chains(m *Manager) []Event {
	var out []Event
	for _, e := range m.Events(0).Events {
		if e.Kind == KindAutomatedChain {
			out = append(out, e)
		}
	}
	return out
}

func TestAutomatedChain(t *testing.T) {
	ms := time.Millisecond
	for _, tc := range []struct {
		name  string
		src   string
		steps []chainStep
		want  bool
	}{
		// thresholds from the lab: R01 (scan, first handshake after 6.3 s), R02 (login 1 ms after the handshake)
		{"agent: scan, handshake, login", "203.0.113.7", []chainStep{{'s', 0}, {'c', 6300 * ms}, {'l', 40 * ms}}, true},
		{"agent at the edge of the window", "203.0.113.7", []chainStep{{'s', 0}, {'c', 17 * time.Second}, {'l', 2900 * ms}}, true},
		{"R01 control: scan and handshakes, no login", "203.0.113.7", []chainStep{{'s', 0}, {'c', 6300 * ms}, {'c', 10 * ms}}, false},
		{"R02 control: logins without a scan", "203.0.113.7", []chainStep{{'c', 0}, {'l', 1 * ms}, {'c', 30 * ms}, {'l', 1 * ms}}, false},
		{"person: types the password", "203.0.113.7", []chainStep{{'s', 0}, {'c', 12 * time.Second}, {'l', 5 * time.Second}}, false},
		{"too slow after the scan", "203.0.113.7", []chainStep{{'s', 0}, {'c', 21 * time.Second}, {'l', 100 * ms}}, false},
		{"login before any handshake", "203.0.113.7", []chainStep{{'s', 0}, {'l', 1 * time.Second}}, false},
		{"ignored own device", "198.51.100.9", []chainStep{{'s', 0}, {'c', 1 * time.Second}, {'l', 10 * ms}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, clk, _ := chainManager(t, false)
			runChain(m, clk, tc.src, tc.steps)
			got := chains(m)
			if (len(got) == 1) != tc.want || len(got) > 1 {
				t.Fatalf("chains %+v", got)
			}
			if tc.want {
				e := got[0]
				if e.Severity != SevHigh || e.Src != tc.src || e.Port != 22 || !strings.Contains(e.Detail, "via=ssh") || !strings.Contains(e.Detail, "scan_to_login=") {
					t.Fatalf("%+v", e)
				}
			}
		})
	}
}

func TestAutomatedChainBanOnceAndReset(t *testing.T) {
	m, clk, banCh := chainManager(t, true)
	runChain(m, clk, "203.0.113.8", []chainStep{{'s', 0}, {'c', time.Second}, {'l', 10 * time.Millisecond}})
	select {
	case b := <-banCh:
		if b.Reason != KindAutomatedChain || b.Src != "203.0.113.8" {
			t.Fatalf("%+v", b)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no ban")
	}
	// more logins of the same chain: no second finding
	runChain(m, clk, "203.0.113.8", []chainStep{{'c', time.Second}, {'l', 10 * time.Millisecond}})
	if n := len(chains(m)); n != 1 {
		t.Fatalf("chains %d", n)
	}
	// a network change forgets half-done chains
	runChain(m, clk, "203.0.113.9", []chainStep{{'s', 0}, {'c', time.Second}})
	if m.chain.size() != 1 {
		t.Fatal("not tracked")
	}
	m.SetNetwork("other", ClassUnknown)
	if m.chain.size() != 0 {
		t.Fatal("not reset")
	}
	// expired entries are pruned by the housekeeping
	runChain(m, clk, "203.0.113.10", []chainStep{{'s', 0}})
	clk.Add(ChainWindow + time.Second)
	m.tick()
	if m.chain.size() != 0 {
		t.Fatal("not pruned")
	}
}

// End to end on a real decoy: a scan finding, then a scripted telnet login
// with the bait password gives both a bait and a chain finding.
func TestAutomatedChainRealDecoy(t *testing.T) {
	pm := &portMap{real: map[int]int{}}
	m, _ := newTestManager(t, pm, nil)
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.DecoyPorts = []int{2323}
	m.Configure(cfg)
	m.SetNetwork("k", ClassUnknown)
	m.Report(Event{Kind: KindScan, Severity: SevHigh, Src: "127.0.0.1", Detail: "mode=many_ports"})
	b, _ := m.dec.bait()
	c := pm.dial(t, 2323)
	c.Write([]byte("deploy\r\n" + b.Password + "\r\n"))
	bufio.NewReader(c).ReadString('P')
	c.Close()
	waitFor(t, "chain", func() bool { return m.Status().Counts[KindAutomatedChain] == 1 && m.Status().Counts[KindBait] == 1 })
	if e := chains(m)[0]; !strings.Contains(e.Detail, "via=bait") {
		t.Fatalf("%+v", e)
	}
}

func TestIsLoginEvent(t *testing.T) {
	for d, want := range map[string]string{
		"ssh login user=root len=1 h=00 client=x": "ssh",
		"telnet login user=a len=1 h=00":          "telnet",
		"http login user=a len=1 h=00 tool=curl":  "http",
		"http GET path=/login":                    "",
		"ssh client SSH-2.0-x login user=":        "",
	} {
		via, ok := isLoginEvent(Event{Kind: KindCowrie, Detail: d})
		if via != want || ok != (want != "") {
			t.Errorf("%q: %q %v", d, via, ok)
		}
	}
}
