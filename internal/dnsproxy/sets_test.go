package dnsproxy

import (
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/engine"
)

type recWriter struct{ adds map[string]int }

func (w *recWriter) Add(set string, addrs []netip.Addr, _ time.Duration) error {
	w.adds[set] += len(addrs)
	return nil
}

func domainPlan(domains ...string) *engine.Plan {
	return &engine.Plan{Rules: []engine.Rule{{Name: "r", Domains: domains, SetV4: "dom1_v4", SetV6: "dom1_v6", Route: &engine.Route{}}}}
}

// After an edit, rule 1 may be another rule: its set must not get the old
// rule's addresses back.
func TestReplayDropsOtherDomains(t *testing.T) {
	w := &recWriter{adds: map[string]int{}}
	p := New(slog.Default(), w)
	if err := p.Update(domainPlan("a.example"), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := p.sets.ensure("dom1_v4", []netip.Addr{netip.MustParseAddr("192.0.2.1")}, time.Hour); err != nil {
		t.Fatal(err)
	}
	w.adds = map[string]int{}
	if err := p.Update(domainPlan("a.example"), nil); err != nil {
		t.Fatal(err)
	}
	if w.adds["dom1_v4a"] != 1 {
		t.Fatalf("same rule: address not replayed: %v", w.adds)
	}
	w.adds = map[string]int{}
	if err := p.Update(domainPlan("b.example"), nil); err != nil {
		t.Fatal(err)
	}
	if len(w.adds) != 0 {
		t.Fatalf("other domains got the old addresses: %v", w.adds)
	}
}
