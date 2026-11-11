package defense

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func expoManager(t *testing.T) (*Manager, *fakeClock, *portMap) {
	pm := &portMap{real: map[int]int{}}
	m, clk := newTestManager(t, pm, nil)
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Features[FeatScan] = Feature{Watch: true, Block: true}
	m.Configure(cfg)
	m.SetNetwork("k", ClassPublic)
	return m, clk, pm
}

func count(m *Manager, k Kind) (n int) {
	for _, e := range m.Events(0).Events {
		if e.Kind == k {
			n++
		}
	}
	return
}

func TestExposedEventAndDecoysOff(t *testing.T) {
	m, _, _ := expoManager(t)
	if len(m.Status().Decoys) == 0 {
		t.Fatal("public network starts decoys")
	}
	m.SetExposure(Exposure{V4: true, Inbound: "open"})
	st := m.Status()
	if !st.Exposed.V4 || len(st.Decoys) != 0 {
		t.Fatalf("exposed: decoys must stop: %+v", st)
	}
	var ev Event
	for _, e := range m.Events(0).Events {
		if e.Kind == KindExposed {
			ev = e
		}
	}
	if ev.Severity != SevHigh || !strings.Contains(ev.Detail, "inbound=open") || !strings.Contains(ev.Detail, "v4") {
		t.Fatalf("%+v", ev)
	}
	heatOpen := st.Heat
	m.SetExposure(Exposure{V4: true, Inbound: "open"}) // unchanged: no second event
	if count(m, KindExposed) != 1 {
		t.Fatal("repeated event")
	}
	m.SetExposure(Exposure{V4: true, Inbound: "closed"}) // change while exposed: again
	if count(m, KindExposed) != 2 {
		t.Fatal("inbound change must warn again")
	}
	if heatOpen < 40 {
		t.Fatalf("open must run hot, got %d", heatOpen)
	}
	m.SetExposure(Exposure{})
	if len(m.Status().Decoys) == 0 {
		t.Fatal("decoys come back when no longer exposed")
	}
}

func TestExposedDecoysOptIn(t *testing.T) {
	m, _, _ := expoManager(t)
	cfg := m.Status().Config
	cfg.DecoysWhenExposed = true
	m.Configure(cfg)
	m.SetExposure(Exposure{V6: true, Inbound: "closed"})
	if len(m.Status().Decoys) == 0 {
		t.Fatal("decoys_when_exposed keeps them")
	}
}

func TestExposedNotWhenDisabled(t *testing.T) {
	m := NewManager(nil)
	defer m.Close()
	m.SetExposure(Exposure{V4: true})
	if len(m.Events(0).Events) != 0 {
		t.Fatal("disabled: no events")
	}
}

func TestFoldEvents(t *testing.T) {
	m, clk, _ := expoManager(t)
	m.SetExposure(Exposure{V4: true, Inbound: "closed"})
	src := "198.51.100.9"
	for i := 0; i < 50; i++ {
		m.Report(Event{Kind: KindCowrie, Severity: SevMedium, Src: src, Detail: "x"})
	}
	if n := count(m, KindCowrie); n != 1 {
		t.Fatalf("folded: %d events in ring", n)
	}
	if m.Status().Counts[KindCowrie] != 50 {
		t.Fatalf("counts still full: %v", m.Status().Counts)
	}
	clk.Add(AggWindow + time.Second)
	m.flushAgg(false)
	var sum Event
	for _, e := range m.Events(0).Events {
		if e.Kind == KindCowrie && strings.HasPrefix(e.Detail, "more=") {
			sum = e
		}
	}
	if sum.Detail != "more=49" || sum.Src != src {
		t.Fatalf("summary %+v", sum)
	}
	// other source, other kind: not folded
	m.Report(Event{Kind: KindCowrie, Severity: SevMedium, Src: "198.51.100.10"})
	m.Report(Event{Kind: KindScan, Severity: SevMedium, Src: src})
	if count(m, KindCowrie) != 3 || count(m, KindScan) != 1 {
		t.Fatal("different key must pass")
	}
	// important kinds are never folded
	for i := 0; i < 3; i++ {
		m.Report(Event{Kind: KindARP, Severity: SevHigh, Src: src})
	}
	if count(m, KindARP) != 3 {
		t.Fatal("arp is not folded")
	}
}

func TestNoFoldWhenNotExposed(t *testing.T) {
	m, _, _ := expoManager(t)
	for i := 0; i < 5; i++ {
		m.Report(Event{Kind: KindCowrie, Severity: SevMedium, Src: "198.51.100.9"})
	}
	if count(m, KindCowrie) != 5 {
		t.Fatal("normal networks keep every event")
	}
}

func TestFoldTableBounded(t *testing.T) {
	m, _, _ := expoManager(t)
	m.SetExposure(Exposure{V4: true, Inbound: "closed"})
	for i := 0; i < AggMax+500; i++ {
		m.Report(Event{Kind: KindDecoyHit, Severity: SevLow, Src: fmt.Sprintf("10.%d.%d.1", i/250, i%250)})
	}
	m.aggMu.Lock()
	n, dropped := len(m.agg), m.aggDropped
	m.aggMu.Unlock()
	if n > AggMax || dropped != 500 {
		t.Fatalf("table %d dropped %d", n, dropped)
	}
	if got := len(m.Events(0).Events); got > 1000 {
		t.Fatalf("ring unbounded: %d", got)
	}
}

func TestRangeBan(t *testing.T) {
	m, _, _ := expoManager(t)
	m.SetExposure(Exposure{V4: true, Inbound: "closed"})
	for i := 1; i <= 3; i++ {
		m.maybeBan(netip.MustParseAddr(fmt.Sprintf("203.0.113.%d", i)), KindScan, FeatScan)
	}
	if got := len(m.Status().Bans); got != 3 {
		t.Fatalf("below threshold: singles, got %d", got)
	}
	m.maybeBan(netip.MustParseAddr("203.0.113.4"), KindScan, FeatScan)
	bans := m.Status().Bans
	if len(bans) != 1 || bans[0].Src != "203.0.113.0/24" {
		t.Fatalf("range ban: %+v", bans)
	}
	m.maybeBan(netip.MustParseAddr("203.0.113.99"), KindScan, FeatScan) // covered
	if len(m.Status().Bans) != 1 {
		t.Fatal("covered address adds nothing")
	}
	m.Unban("203.0.113.0/24")
	if len(m.Status().Bans) != 0 {
		t.Fatal("range lifts")
	}
	// IPv6: /64
	for i := 1; i <= 4; i++ {
		m.maybeBan(netip.MustParseAddr(fmt.Sprintf("2001:db8:1:2::%x", i)), KindScan, FeatScan)
	}
	if b := m.Status().Bans; len(b) != 1 || b[0].Src != "2001:db8:1:2::/64" {
		t.Fatalf("v6 range: %+v", b)
	}
}

func TestRangeBanSkipsNeverRange(t *testing.T) {
	m, _, _ := expoManager(t)
	m.SetExposure(Exposure{V4: true, Inbound: "closed"})
	m.SetNever([]netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")}) // the gateway sits in the same /24
	for i := 10; i < 20; i++ {
		m.maybeBan(netip.MustParseAddr(fmt.Sprintf("192.0.2.%d", i)), KindScan, FeatScan)
	}
	for _, b := range m.Status().Bans {
		if strings.Contains(b.Src, "/") {
			t.Fatalf("a range holding the gateway must not be blocked: %v", b)
		}
	}
}

func TestNoRangeBanWhenNotExposed(t *testing.T) {
	m, _, _ := expoManager(t)
	for i := 1; i <= 6; i++ {
		m.maybeBan(netip.MustParseAddr(fmt.Sprintf("203.0.113.%d", i)), KindScan, FeatScan)
	}
	if len(m.Status().Bans) != 6 {
		t.Fatal("singles outside exposed networks")
	}
}

func TestBanTableCap(t *testing.T) {
	b := NewBans()
	b.Max = 10
	var gone []string
	b.OnUnban = func(x Ban) { gone = append(gone, x.Src) }
	for i := 0; i < 25; i++ {
		b.Add(fmt.Sprintf("198.51.100.%d", i), KindScan, time.Duration(i+1)*time.Minute)
	}
	if b.Len() != 10 || len(gone) != 15 {
		t.Fatalf("len %d evicted %d", b.Len(), len(gone))
	}
	if b.Has("198.51.100.0") || !b.Has("198.51.100.24") {
		t.Fatal("the soonest-expiring entry makes room")
	}
}
