package defense

import (
	"testing"
	"time"
)

func TestProbeGate(t *testing.T) {
	now := time.Unix(1000, 0)
	g := &probeGate{gap: 20 * time.Second, now: func() time.Time { return now }}
	if !g.Allow() {
		t.Fatal("first")
	}
	now = now.Add(5 * time.Second)
	if g.Allow() {
		t.Fatal("too soon")
	}
	now = now.Add(16 * time.Second)
	if !g.Allow() {
		t.Fatal("after gap")
	}
}

func TestProbeSoonNoop(t *testing.T) {
	(&Sensors{}).ProbeSoon() // not running: no panic, no block
	s := &Sensors{kick: make(chan struct{}, 1)}
	s.ProbeSoon()
	s.ProbeSoon() // full: no block
	if len(s.kick) != 1 {
		t.Fatal("kick not queued once")
	}
}
