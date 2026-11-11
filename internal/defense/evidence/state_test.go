package evidence

import (
	"strings"
	"testing"
	"time"
)

func TestStateWatchJumpsAndSync(t *testing.T) {
	clk := &clock{time.Date(2026, 11, 11, 8, 0, 0, 0, time.UTC)}
	synced := true
	w := &StateWatch{Synced: func() (bool, bool) { return synced, true }, Now: clk.now}
	l, _ := newLog(t, clk, func(o *Options) { o.Preamble = w.Preamble })
	w.Log = l
	w.SetNet("public", clk.t.Add(-time.Minute))
	w.CheckAt(clk.t, 0, true)
	clk.t = clk.t.Add(30 * time.Second)
	w.CheckAt(clk.t, 30*time.Second, true) // normal
	clk.t = clk.t.Add(30 * time.Minute)
	w.CheckAt(clk.t, 30*time.Second, true) // wall moved 30 min, monotonic 30 s
	synced = false
	w.CheckAt(clk.t.Add(time.Second), time.Second, true)
	es, _ := l.Read(Filter{})
	var kinds []string
	for _, e := range es {
		kinds = append(kinds, e.Kind)
	}
	got := strings.Join(kinds, ",")
	if !strings.Contains(got, "clock_jump") || strings.Count(got, "state_clock") < 2 {
		t.Fatalf("kinds %s", got)
	}
	for _, e := range es {
		if e.Kind == "state_net" && !strings.HasPrefix(e.Detail, "class=public joined=") {
			t.Fatalf("state_net %q", e.Detail)
		}
	}
	// real clocks do not produce a jump
	w2 := &StateWatch{Log: l}
	w2.Check()
	w2.Check()
	es2, _ := l.Read(Filter{})
	if len(es2) != len(es) {
		for _, e := range es2[len(es):] {
			t.Logf("%+v", e)
		}
		t.Fatal("no jump expected from the real clock")
	}
}
