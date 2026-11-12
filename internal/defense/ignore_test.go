package defense

import (
	"strings"
	"testing"
	"time"
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

func TestStartGraceObservesOnly(t *testing.T) {
	clk := newClock()
	m := NewManager(nil, WithClock(clk.Now), WithStartGrace(30*time.Second))
	t.Cleanup(m.Close)
	cfg := DefaultConfig()
	cfg.Enabled = true
	m.Configure(cfg)
	m.SetNetwork("net1", ClassUnknown)
	src := mustAddr("192.0.2.9")
	for i := 0; i < 15; i++ {
		m.ObserveState(src, 22000, "tcp", StateS0)
	}
	if hasKind(m, KindBruteForce) {
		t.Fatal("reported in the grace time")
	}
	clk.Add(2 * time.Minute)
	for i := 0; i < 15; i++ {
		m.ObserveState(src, 22000, "tcp", StateS0)
	}
	if !hasKind(m, KindBruteForce) {
		t.Fatal("must report after the grace time")
	}
}

func TestIsTCPReply(t *testing.T) {
	pkt := func(flags byte) []byte {
		p := make([]byte, 20+20)
		p[0], p[9] = 0x45, 6
		p[20+13] = flags
		return p
	}
	for f, want := range map[byte]bool{0x02: false, 0x12: true, 0x10: true, 0x04: true, 0x14: true, 0x00: false} {
		if IsTCPReply(pkt(f)) != want {
			t.Errorf("flags %#x", f)
		}
	}
	if IsTCPReply([]byte{0x45}) || IsTCPReply(nil) {
		t.Error("short packet")
	}
}

// A peer inside a VPN is a source like any other: nothing makes it known by
// itself (owner's decision, a compromised peer must keep standing out). Only
// entries the user wrote are on the ignore list.
func TestVPNPeerNotKnownAutomatically(t *testing.T) {
	m := scanManager(t, nil)
	m.SetNever(ParsePrefixes([]string{"203.0.113.1"})) // automatic part: gateway, DNS, tunnel endpoints
	peer := mustAddr("198.51.100.25")                  // an address inside the VPN
	for i := 0; i < 30; i++ {
		m.ObserveState(peer, 22000, "tcp", StateS0)
	}
	if !hasKind(m, KindBruteForce) {
		t.Fatal("a VPN peer must be reported like any other source")
	}
	if m.ignore.Match(peer, 22000) {
		t.Fatal("peer is on the ignore list without the user adding it")
	}
}
