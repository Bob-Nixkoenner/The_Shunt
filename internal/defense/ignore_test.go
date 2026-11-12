package defense

import (
	"strings"
	"testing"
)

func TestValidateIgnore(t *testing.T) {
	ok := []IgnoreEntry{{Addr: "192.0.2.5", Name: "Test device"}, {Addr: "198.51.100.0/24", Ports: []int{22000, 80}}, {Addr: "2001:db8::/48"}}
	if err := ValidateIgnore(ok); err != nil {
		t.Fatal(err)
	}
	bad := []IgnoreEntry{
		{Addr: "nonsense"}, {Addr: "0.0.0.0/0"}, {Addr: "10.0.0.0/4"}, {Addr: "224.0.0.1"},
		{Addr: "192.0.2.5", Ports: []int{0}}, {Addr: "192.0.2.5", Ports: []int{70000}}, {Addr: "192.0.2.5", Ports: []int{5, 5}},
		{Addr: "192.0.2.5", Name: "line\nbreak"}, {Addr: "192.0.2.5", Name: strings.Repeat("x", MaxIgnoreName+1)},
		{Addr: "192.0.2.5", Ports: make([]int, MaxIgnorePorts+1)},
	}
	for i, e := range bad {
		if err := ValidateIgnore([]IgnoreEntry{e}); err == nil {
			t.Errorf("entry %d accepted: %+v", i, e)
		}
	}
	if ValidateIgnore(make([]IgnoreEntry, MaxIgnoreEntries+1)) == nil {
		t.Error("too many entries accepted")
	}
}

func TestIgnoreSetMatch(t *testing.T) {
	var s IgnoreSet
	s.Set([]IgnoreEntry{{Addr: "192.0.2.5"}, {Addr: "198.51.100.0/24", Ports: []int{22000}}})
	for _, c := range []struct {
		a    string
		port int
		want bool
	}{{"192.0.2.5", 1, true}, {"192.0.2.5", 0, true}, {"192.0.2.6", 1, false},
		{"198.51.100.9", 22000, true}, {"198.51.100.9", 22, false}, {"198.51.100.9", 0, false}} {
		if got := s.Match(mustAddr(c.a), c.port); got != c.want {
			t.Errorf("%s:%d = %v", c.a, c.port, got)
		}
	}
}

func scanManager(t *testing.T, ign []IgnoreEntry) *Manager {
	m, _ := newTestManager(t, &portMap{real: map[int]int{}}, nil)
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Ignore = ign
	m.Configure(cfg)
	m.SetNetwork("net1", ClassUnknown)
	return m
}

func hasKind(m *Manager, k Kind) bool {
	for _, e := range m.Events(0).Events {
		if e.Kind == k {
			return true
		}
	}
	return false
}

func TestIgnoredSourceCausesNoBruteForce(t *testing.T) {
	src := mustAddr("192.0.2.5")
	m := scanManager(t, []IgnoreEntry{{Addr: "192.0.2.5", Name: "peer", Ports: []int{22000}}})
	for i := 0; i < 30; i++ {
		m.ObserveState(src, 22000, "tcp", StateS0)
	}
	if hasKind(m, KindBruteForce) || hasKind(m, KindScan) {
		t.Fatal("ignored port reported")
	}
	// other port of the same device is not ignored
	for i := 0; i < 30; i++ {
		m.ObserveState(src, 23, "tcp", StateS0)
	}
	if !hasKind(m, KindBruteForce) {
		t.Fatal("port outside the entry must still count")
	}
	// all ports
	m2 := scanManager(t, []IgnoreEntry{{Addr: "192.0.2.0/24"}})
	for p := 1; p < 40; p++ {
		m2.ObserveState(src, p, "tcp", StateREJ)
	}
	if hasKind(m2, KindScan) {
		t.Fatal("ignored source reported a scan")
	}
	if m2.Status().Heat != 0 {
		t.Fatal("heat from ignored source")
	}
}

func TestIgnoreKeepsReputation(t *testing.T) {
	m := scanManager(t, []IgnoreEntry{{Addr: "192.0.2.5"}})
	m.Report(Event{Kind: KindReputation, Severity: SevHigh, Src: "192.0.2.5", Detail: "list=feodo"})
	m.Report(Event{Kind: KindDecoyHit, Severity: SevMedium, Src: "192.0.2.5", Port: 22})
	if !hasKind(m, KindReputation) || hasKind(m, KindDecoyHit) {
		t.Fatal("reputation must stay, decoy hit must go")
	}
}
