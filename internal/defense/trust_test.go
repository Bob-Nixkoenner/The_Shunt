package defense

import (
	"net/netip"
	"testing"
	"time"
)

func TestTrustSteps(t *testing.T) {
	now := time.Now()
	var s IgnoreSet
	s.Set([]IgnoreEntry{
		{Addr: "192.0.2.5", Level: TrustKnown},
		{Addr: "192.0.2.6", Level: TrustTest, Until: now.Add(time.Hour).Unix()},
		{Addr: "192.0.2.7", Level: TrustTest, Until: now.Add(-time.Second).Unix()},
		{Addr: "192.0.2.8", Level: TrustKnown, Ports: []int{22000}},
	})
	for _, c := range []struct {
		a    string
		port int
		want string
	}{{"192.0.2.5", 80, TrustKnown}, {"192.0.2.6", 80, TrustTest}, {"192.0.2.7", 80, ""},
		{"192.0.2.8", 22000, TrustKnown}, {"192.0.2.8", 22, ""}, {"192.0.2.9", 1, ""}} {
		if got := s.Trust(mustAddr(c.a), c.port, now); got != c.want {
			t.Errorf("%s:%d = %q want %q", c.a, c.port, got, c.want)
		}
	}
	if s.Match(mustAddr("192.0.2.5"), 80) {
		t.Error("known source must not be fully ignored")
	}
	if s.TrustAny(mustAddr("192.0.2.8"), now) != TrustKnown {
		t.Error("block check ignores ports")
	}
	if ValidateIgnore([]IgnoreEntry{{Addr: "192.0.2.5", Level: TrustTest}}) == nil || ValidateIgnore([]IgnoreEntry{{Addr: "192.0.2.5", Level: "x"}}) == nil {
		t.Error("bad level accepted")
	}
}

func TestThermoKnownTest(t *testing.T) {
	th := NewThermo()
	for i := 0; i < 200; i++ {
		th.Add(Event{Kind: KindScan, Severity: SevHigh, Trust: TrustKnown})
	}
	if h := th.Heat(); h != KnownHeatCap {
		t.Errorf("known heat = %d, want cap %d", h, KnownHeatCap)
	}
	t2 := NewThermo()
	t2.Add(Event{Kind: KindScan, Severity: SevHigh})
	full := t2.Heat()
	t3 := NewThermo()
	t3.Add(Event{Kind: KindScan, Severity: SevHigh, Trust: TrustKnown})
	if t3.Heat() >= full || t3.Heat() == 0 {
		t.Errorf("known heat %d vs normal %d", t3.Heat(), full)
	}
	t4 := NewThermo()
	t4.Add(Event{Kind: KindScan, Severity: SevHigh, Trust: TrustTest})
	if t4.Heat() != 0 {
		t.Error("test adds heat")
	}
}

func TestKnownShownNotBlockedNotReported(t *testing.T) {
	m := scanManager(t, []IgnoreEntry{{Addr: "192.0.2.5", Level: TrustKnown}})
	var hooked int
	m.onEvent = func(Event, Class) { hooked++ }
	m.Report(Event{Kind: KindScan, Severity: SevHigh, Src: "192.0.2.5"})
	m.Report(Event{Kind: KindScan, Severity: SevHigh, Src: "192.0.2.99"})
	var tagged int
	for _, e := range m.Events(0).Events {
		if e.Kind == KindScan && e.Trust == TrustKnown {
			tagged++
		}
	}
	if tagged != 1 || hooked != 1 {
		t.Errorf("tagged=%d hooked=%d, want 1 and 1", tagged, hooked)
	}
}

// A test entry ends at most TestMaxSeconds after the list was loaded, however
// far away its end time is.
func TestTrustTestCapped(t *testing.T) {
	var s IgnoreSet
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	a := netip.MustParseAddr("198.51.100.30")
	s.setAt([]IgnoreEntry{{Addr: a.String(), Level: TrustTest, Until: now.AddDate(10, 0, 0).Unix()}}, now)
	if got := s.Trust(a, 22, now.Add(23*time.Hour)); got != TrustTest {
		t.Fatalf("within the cap: %q", got)
	}
	if got := s.Trust(a, 22, now.Add(TestMaxSeconds*time.Second)); got != "" {
		t.Fatalf("after the cap the source counts normally: %q", got)
	}
	// a short end time stays as it is
	s.setAt([]IgnoreEntry{{Addr: a.String(), Level: TrustTest, Until: now.Add(time.Hour).Unix()}}, now)
	if got := s.Trust(a, 22, now.Add(2*time.Hour)); got != "" {
		t.Fatalf("one hour entry: %q", got)
	}
}
