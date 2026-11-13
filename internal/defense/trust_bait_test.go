package defense

import (
	"net/netip"
	"testing"
	"time"
)

// A source on the list as "known" or "test" that uses the lock credentials
// of a bait file or runs a scripted chain is shown (tagged), never reported
// and never blocked, also with blocking on. Decision of 2026-11-13: the
// user vouched for the device, so even proof of an attack only shows; a
// stranger with the same steps is blocked as before.
func TestTrustedSourceBaitAndChainShownNeverBlocked(t *testing.T) {
	m, clk, banCh := chainManager(t, true)
	cfg := m.Status().Config
	cfg.Ignore = []IgnoreEntry{
		{Addr: "192.0.2.5", Name: "own scanner", Level: TrustKnown},
		{Addr: "192.0.2.6", Name: "own test", Level: TrustTest, Until: clk.Now().Add(time.Hour).Unix()},
	}
	m.Configure(cfg)
	var hooked []Event
	m.onEvent = func(ev Event, _ Class) { hooked = append(hooked, ev) }
	bait := func(src string) {
		m.decoyHit(Hit{Src: netip.MustParseAddr(src), Port: 23, Kind: KindBait, Sev: SevHigh, Detail: "bait used via=telnet user=root"})
	}
	for _, src := range []string{"192.0.2.5", "192.0.2.6"} {
		bait(src)
		runChain(m, clk, src, []chainStep{{'s', 0}, {'c', time.Second}, {'l', 10 * time.Millisecond}})
	}
	select {
	case b := <-banCh:
		t.Fatalf("trusted source blocked: %+v", b)
	case <-time.After(300 * time.Millisecond):
	}
	if n := len(m.Status().Bans); n != 0 {
		t.Fatalf("%d bans", n)
	}
	if len(hooked) != 0 {
		t.Fatalf("reported: %+v", hooked)
	}
	want := map[string]string{"192.0.2.5": TrustKnown, "192.0.2.6": TrustTest}
	seen := map[Kind]int{}
	for _, e := range m.Events(0).Events {
		if e.Kind != KindBait && e.Kind != KindAutomatedChain {
			continue
		}
		if e.Trust != want[e.Src] {
			t.Errorf("%s from %s: trust %q, want %q", e.Kind, e.Src, e.Trust, want[e.Src])
		}
		seen[e.Kind]++
	}
	if seen[KindBait] != 2 || seen[KindAutomatedChain] != 2 {
		t.Fatalf("shown %v, want 2 bait and 2 chain findings", seen)
	}

	// control: a stranger is blocked at once for the bait use
	bait("203.0.113.20")
	select {
	case b := <-banCh:
		if b.Reason != KindBait || b.Src != "203.0.113.20" {
			t.Fatalf("%+v", b)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stranger not blocked")
	}
	if len(hooked) == 0 {
		t.Fatal("stranger not reported")
	}
}
