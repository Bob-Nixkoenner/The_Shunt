package defense

import (
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeTable is a connection table for the brute-force counter.
type fakeTable struct {
	mu    sync.Mutex
	flows map[string]ServiceFlows // "src|port"
	fail  bool
	calls atomic.Int64
	panic bool
}

func (f *fakeTable) set(src string, port int, fl ServiceFlows) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.flows == nil {
		f.flows = map[string]ServiceFlows{}
	}
	f.flows[fmt.Sprintf("%s|%d", src, port)] = fl
}

func (f *fakeTable) probe(src netip.Addr, port int) (ServiceFlows, bool) {
	f.calls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.panic {
		panic("table reader bug")
	}
	if f.fail {
		return ServiceFlows{}, false
	}
	return f.flows[fmt.Sprintf("%s|%d", src, port)], true
}

func svcManager(t *testing.T, block bool, tab *fakeTable, ignore ...IgnoreEntry) (*Manager, *fakeClock, chan Ban) {
	t.Helper()
	clk := newClock()
	banCh := make(chan Ban, 16)
	opts := []Option{WithListen((&portMap{real: map[int]int{}}).listen), WithClock(clk.Now),
		WithBanHooks(func(b Ban) { banCh <- b }, nil)}
	if tab != nil {
		opts = append(opts, WithServiceProbe(tab.probe))
	}
	m := NewManager(slog.New(slog.NewTextHandler(io.Discard, nil)), opts...)
	t.Cleanup(m.Close)
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.DecoyPorts = nil
	cfg.Features[FeatBrute] = Feature{Watch: true, Block: block}
	cfg.Ignore = ignore
	m.Configure(cfg)
	m.SetNetwork("k", ClassUnknown)
	return m, clk, banCh
}

// conns feeds n new connections from src to port, one every gap.
func conns(m *Manager, clk *fakeClock, src string, port, n int, gap time.Duration) {
	a := netip.MustParseAddr(src)
	for i := 0; i < n; i++ {
		m.ObserveService(a, port, "tcp", "sshd")
		clk.Add(gap)
	}
}

func svcEvents(m *Manager) []Event {
	var out []Event
	for _, e := range m.Events(0).Events {
		if e.Kind == KindBruteService {
			out = append(out, e)
		}
	}
	return out
}

func bans(ch chan Ban) []Ban {
	var out []Ban
	for {
		select {
		case b := <-ch:
			out = append(out, b)
		default:
			return out
		}
	}
}

// R02: the scripted guesser made 10 connections (one login each) within
// its 30 s limit. The connections ended after a handshake.
func TestBruteServiceLabR02(t *testing.T) {
	tab := &fakeTable{}
	tab.set("203.0.113.7", 22, ServiceFlows{Open: 1, Done: 9})
	m, clk, banCh := svcManager(t, true, tab)
	conns(m, clk, "203.0.113.7", 22, 11, 3*time.Second)
	ev := svcEvents(m)
	if len(ev) != 1 {
		t.Fatalf("want one brute_service event, got %v", ev)
	}
	e := ev[0]
	if e.Severity != SevMedium || e.Port != 22 || e.Proto != "tcp" || e.Src != "203.0.113.7" {
		t.Fatalf("event %+v", e)
	}
	for _, want := range []string{"service=sshd", "short=10", "open=1", "handshake=yes"} {
		if !strings.Contains(e.Detail, want) {
			t.Fatalf("detail %q lacks %q", e.Detail, want)
		}
	}
	if strings.Contains(e.Detail, "block=waits") {
		t.Fatalf("handshake proven, nothing waits: %q", e.Detail)
	}
	b := bans(banCh)
	if len(b) != 1 || b[0].Src != "203.0.113.7" || b[0].Reason != KindBruteService {
		t.Fatalf("bans %+v", b)
	}
}

// hydra-like: 16 parallel tasks, 80 connections in 20 s -> medium, then high.
func TestBruteServiceHighRate(t *testing.T) {
	tab := &fakeTable{}
	tab.set("203.0.113.8", 3306, ServiceFlows{Open: 16})
	m, clk, banCh := svcManager(t, true, tab)
	conns(m, clk, "203.0.113.8", 3306, 80, 250*time.Millisecond)
	ev := svcEvents(m)
	if len(ev) != 2 || ev[0].Severity != SevMedium || ev[1].Severity != SevHigh {
		t.Fatalf("want medium then high, got %+v", ev)
	}
	if len(bans(banCh)) != 1 {
		t.Fatal("one block expected")
	}
	// a further minute at the same rate: one more round, not one per packet
	conns(m, clk, "203.0.113.8", 3306, 240, 250*time.Millisecond)
	if n := len(svcEvents(m)); n > 4 {
		t.Fatalf("events must not grow per packet: %d", n)
	}
}

// Controls: none of these may raise anything.
func TestBruteServiceControls(t *testing.T) {
	t.Run("web client 6 connections in 10 s", func(t *testing.T) {
		tab := &fakeTable{}
		m, clk, banCh := svcManager(t, true, tab)
		conns(m, clk, "203.0.113.20", 443, 6, 10*time.Second/6)
		clk.Add(time.Minute)
		conns(m, clk, "203.0.113.20", 443, 6, 10*time.Second/6) // a reload later
		if len(svcEvents(m)) != 0 || len(bans(banCh)) != 0 {
			t.Fatal("a browser must not count as brute force")
		}
		if tab.calls.Load() != 0 {
			t.Fatal("below the threshold the table is not read")
		}
	})
	t.Run("syncthing-like long-running traffic", func(t *testing.T) {
		tab := &fakeTable{}
		tab.set("203.0.113.21", 22000, ServiceFlows{Open: 2})
		m, clk, banCh := svcManager(t, true, tab)
		// two hours: the peer keeps its connections and reconnects every
		// 30 s at most (discovery, relay change)
		conns(m, clk, "203.0.113.21", 22000, 240, 30*time.Second)
		if len(svcEvents(m)) != 0 || len(bans(banCh)) != 0 {
			t.Fatal("long-running sync traffic must stay quiet")
		}
	})
	t.Run("keep-alive pool: connections stay open", func(t *testing.T) {
		tab := &fakeTable{}
		tab.set("203.0.113.22", 8080, ServiceFlows{Open: 14})
		m, clk, banCh := svcManager(t, true, tab)
		conns(m, clk, "203.0.113.22", 8080, 14, 2*time.Second)
		if len(svcEvents(m)) != 0 || len(bans(banCh)) != 0 {
			t.Fatalf("open connections are not short: %v", svcEvents(m))
		}
	})
	t.Run("R01 port scan: one connection per port", func(t *testing.T) {
		tab := &fakeTable{}
		m, clk, _ := svcManager(t, true, tab)
		a := netip.MustParseAddr("203.0.113.23")
		for p := 1; p <= 1024; p++ {
			m.ObserveService(a, p, "tcp", "")
			clk.Add(10 * time.Millisecond)
		}
		if len(svcEvents(m)) != 0 {
			t.Fatal("a scan is not brute force on a service")
		}
	})
	t.Run("udp is not counted", func(t *testing.T) {
		m, clk, _ := svcManager(t, true, nil)
		for i := 0; i < 50; i++ {
			m.ObserveService(netip.MustParseAddr("203.0.113.24"), 53, "udp", "")
			clk.Add(100 * time.Millisecond)
		}
		if len(svcEvents(m)) != 0 {
			t.Fatal("udp counted")
		}
	})
}

// A bare SYN flood proves nothing about the source address: reported, never
// blocked. The block follows once the table shows a finished handshake.
func TestBruteServiceSynOnlyNeverBlocks(t *testing.T) {
	tab := &fakeTable{}
	tab.set("203.0.113.30", 22, ServiceFlows{}) // SYN_RECV/CLOSE only
	m, clk, banCh := svcManager(t, true, tab)
	conns(m, clk, "203.0.113.30", 22, 40, time.Second)
	ev := svcEvents(m)
	if len(ev) != 1 || !strings.Contains(ev[0].Detail, "handshake=no") || !strings.Contains(ev[0].Detail, "block=waits_for_handshake") {
		t.Fatalf("events %+v", ev)
	}
	if b := bans(banCh); len(b) != 0 {
		t.Fatalf("bare SYNs must never block: %+v", b)
	}
	if v, _ := m.ver.sizes(); v != 0 {
		t.Fatal("no handshake must be noted")
	}
	// now the source finishes handshakes with the service
	tab.set("203.0.113.30", 22, ServiceFlows{Done: SvcBruteConns})
	conns(m, clk, "203.0.113.30", 22, 6, time.Second)
	if b := bans(banCh); len(b) != 1 || b[0].Reason != KindBruteService {
		t.Fatalf("block after the handshake: %+v", b)
	}
}

// Ban spoofing: a forger sends SYNs in the name of a device that holds one
// real connection to the service (a phone with Syncthing or SSH open). One
// proven handshake must not stand for the forged ones: reported, no block,
// and the device is not marked as verified (that would let forged scans
// block it at once afterwards).
func TestBruteServiceForgedSYNsBesideOneRealConnection(t *testing.T) {
	tab := &fakeTable{}
	tab.set("198.51.100.20", 22, ServiceFlows{Open: 1}) // the device's own session
	m, clk, banCh := svcManager(t, true, tab)
	conns(m, clk, "198.51.100.20", 22, 70, 500*time.Millisecond) // forged SYNs
	ev := svcEvents(m)
	if len(ev) == 0 || !strings.Contains(ev[0].Detail, "handshake=no") {
		t.Fatalf("events %+v", ev)
	}
	if b := bans(banCh); len(b) != 0 {
		t.Fatalf("one real connection must not prove forged ones: %+v", b)
	}
	if m.ver.confirmed(netip.MustParseAddr("198.51.100.20"), clk.Now()) {
		t.Fatal("the device must not be marked as verified")
	}
	// a few closed sessions of its own are still not enough
	tab.set("198.51.100.20", 22, ServiceFlows{Open: 1, Done: SvcBruteConns - 2})
	conns(m, clk, "198.51.100.20", 22, 12, 500*time.Millisecond)
	if b := bans(banCh); len(b) != 0 {
		t.Fatalf("%d proven connections must not block: %+v", SvcBruteConns-1, b)
	}
}

// Without a readable table: reported (handshake=unknown), never blocked.
func TestBruteServiceNoTable(t *testing.T) {
	for _, tab := range []*fakeTable{nil, {fail: true}} {
		var m *Manager
		var clk *fakeClock
		var banCh chan Ban
		if tab == nil {
			m, clk, banCh = svcManager(t, true, nil)
		} else {
			m, clk, banCh = svcManager(t, true, tab)
		}
		conns(m, clk, "203.0.113.31", 22, 12, time.Second)
		ev := svcEvents(m)
		if len(ev) != 1 || !strings.Contains(ev[0].Detail, "handshake=unknown") {
			t.Fatalf("events %+v", ev)
		}
		if len(bans(banCh)) != 0 {
			t.Fatal("no proof, no block")
		}
	}
}

func TestBruteServiceBlockOff(t *testing.T) {
	tab := &fakeTable{}
	tab.set("203.0.113.32", 22, ServiceFlows{Done: SvcBruteConns})
	m, clk, banCh := svcManager(t, false, tab)
	conns(m, clk, "203.0.113.32", 22, 30, time.Second)
	ev := svcEvents(m)
	if len(ev) != 1 || strings.Contains(ev[0].Detail, "block=") {
		t.Fatalf("events %+v", ev)
	}
	if len(bans(banCh)) != 0 {
		t.Fatal("blocking of brute is off")
	}
}

// Own devices at every trust step, the never list (gateway, DNS, tunnel
// endpoints), loopback and own addresses never count.
func TestBruteServiceExempt(t *testing.T) {
	tab := &fakeTable{}
	ign := []IgnoreEntry{
		{Addr: "198.51.100.10", Name: "own device"},
		{Addr: "198.51.100.11", Name: "known device", Level: TrustKnown},
		{Addr: "198.51.100.12", Name: "own scan", Level: TrustTest, Until: newClock().Now().Add(time.Hour).Unix()},
		{Addr: "198.51.100.13", Name: "only sync", Ports: []int{22000}},
	}
	m, clk, banCh := svcManager(t, true, tab, ign...)
	m.SetNever([]netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")}) // gateway
	m.ownAddr = func(a netip.Addr) bool { return a == netip.MustParseAddr("192.0.2.50") }
	for _, src := range []string{"198.51.100.10", "198.51.100.11", "198.51.100.12", "192.0.2.1", "192.0.2.50", "127.0.0.1", "::1"} {
		tab.set(src, 22, ServiceFlows{Done: SvcBruteConns})
		conns(m, clk, src, 22, 70, 100*time.Millisecond)
	}
	conns(m, clk, "198.51.100.13", 22000, 70, 100*time.Millisecond)
	if ev := svcEvents(m); len(ev) != 0 {
		t.Fatalf("exempt sources raised %+v", ev)
	}
	if len(bans(banCh)) != 0 || tab.calls.Load() != 0 {
		t.Fatal("exempt sources must not even be looked up")
	}
	// the port-limited entry covers only its port
	tab.set("198.51.100.13", 22, ServiceFlows{Done: SvcBruteConns})
	conns(m, clk, "198.51.100.13", 22, 12, time.Second)
	if len(svcEvents(m)) != 1 {
		t.Fatal("other ports of a port-limited entry count")
	}
}

func TestBruteServiceWindowAndReset(t *testing.T) {
	tab := &fakeTable{}
	tab.set("203.0.113.40", 22, ServiceFlows{Done: SvcBruteConns})
	m, clk, _ := svcManager(t, false, tab)
	conns(m, clk, "203.0.113.40", 22, 9, 6*time.Second) // 9 in 54 s: below
	if len(svcEvents(m)) != 0 {
		t.Fatal("below threshold")
	}
	clk.Add(20 * time.Second)
	conns(m, clk, "203.0.113.40", 22, 9, 7*time.Second) // never 10 within 60 s
	if len(svcEvents(m)) != 0 {
		t.Fatal("old connections must leave the window")
	}
	conns(m, clk, "203.0.113.40", 22, 12, time.Second)
	if len(svcEvents(m)) != 1 {
		t.Fatal("first finding")
	}
	clk.Add(2 * time.Minute)
	conns(m, clk, "203.0.113.40", 22, 12, time.Second)
	if len(svcEvents(m)) != 2 {
		t.Fatal("a new window reports again")
	}
	m.SetNetwork("other", ClassUnknown)
	if m.svc.size() != 0 {
		t.Fatal("a network change forgets the counts")
	}
}

func TestBruteServiceStartGrace(t *testing.T) {
	tab := &fakeTable{}
	m, clk, _ := svcManager(t, true, tab)
	m.grace = 30 * time.Second
	m.started = clk.Now()
	conns(m, clk, "203.0.113.41", 22, 20, time.Second)
	if len(svcEvents(m)) != 0 {
		t.Fatal("observe only during the start grace")
	}
}

// Memory: caps per source and in total; a flood of sources or ports does
// not grow the table past them.
func TestBruteServiceCaps(t *testing.T) {
	m, clk, _ := svcManager(t, false, nil)
	src := netip.MustParseAddr("203.0.113.50")
	for p := 1; p <= 100; p++ {
		m.ObserveService(src, p, "tcp", "")
	}
	m.svc.mu.Lock()
	n := m.svc.perSrc[src]
	m.svc.mu.Unlock()
	if n != svcMaxPortsPerS {
		t.Fatalf("ports per source %d", n)
	}
	for i := 0; i < svcMaxEntries+500; i++ {
		a := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		m.ObserveService(a, 22, "tcp", "")
	}
	if s := m.svc.size(); s > svcMaxEntries {
		t.Fatalf("entries %d > cap", s)
	}
	m.svc.mu.Lock()
	dropped := m.svc.dropped
	m.svc.mu.Unlock()
	if dropped == 0 {
		t.Fatal("overflow must be counted")
	}
	// after the window the housekeeping makes room again
	clk.Add(2 * SvcBruteWindow)
	m.tick()
	if m.svc.size() != 0 {
		t.Fatalf("prune left %d", m.svc.size())
	}
}

// The table is read rarely: once per pair every 5 s, once per second over all.
func TestBruteServiceProbeRate(t *testing.T) {
	tab := &fakeTable{}
	tab.set("203.0.113.60", 22, ServiceFlows{}) // never a handshake: keeps asking
	m, clk, _ := svcManager(t, true, tab)
	conns(m, clk, "203.0.113.60", 22, 600, 100*time.Millisecond) // 60 s, 10/s
	if c := tab.calls.Load(); c < 2 || c > 13 {
		t.Fatalf("table read %d times in 60 s", c)
	}
}

// A bug in the table reader is caught; the counter goes on working.
func TestBruteServiceProbePanic(t *testing.T) {
	tab := &fakeTable{panic: true}
	m, clk, banCh := svcManager(t, true, tab)
	before := Faults()
	conns(m, clk, "203.0.113.70", 22, 12, time.Second)
	if Faults() == before {
		t.Fatal("panic not caught")
	}
	ev := svcEvents(m)
	if len(ev) != 1 || !strings.Contains(ev[0].Detail, "handshake=unknown") || len(bans(banCh)) != 0 {
		t.Fatalf("events %+v", ev)
	}
	// lock released: the next connection works
	m.ObserveService(netip.MustParseAddr("203.0.113.71"), 22, "tcp", "")
}

func TestServiceLabel(t *testing.T) {
	for in, want := range map[string]string{"": "unknown", "sshd": "sshd", "a b\x00c": "a_b_c", strings.Repeat("x", 50): strings.Repeat("x", 32)} {
		if got := serviceLabel(in); got != want {
			t.Fatalf("%q -> %q", in, got)
		}
	}
}

func TestBruteServiceRace(t *testing.T) {
	tab := &fakeTable{}
	m, _, _ := svcManager(t, true, tab)
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 300; i++ {
				a := netip.AddrFrom4([4]byte{203, 0, 113, byte(g*10 + i%5)})
				tab.set(a.String(), 22, ServiceFlows{Done: SvcBruteConns * (1 - i%2)})
				m.ObserveService(a, 22, "tcp", "sshd")
				if i%50 == 0 {
					m.tick()
				}
			}
		}(g)
	}
	wg.Wait()
}

// The clock going back (NTP step) must not count connections twice.
func TestSvcEntryClockBack(t *testing.T) {
	var e svcEntry
	for s := int64(1000); s < 1009; s++ {
		e.add(s) // 9 in 9 s
	}
	for s := int64(1000); s < 1009; s++ {
		e.add(s) // the same seconds again after a step back
	}
	if n := e.count(); n >= SvcBruteConns+8 {
		t.Fatalf("counted twice after the clock went back: %d", n)
	}
}
