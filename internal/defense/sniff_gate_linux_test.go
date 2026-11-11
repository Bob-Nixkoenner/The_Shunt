package defense

import (
	"context"
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

// A requested probe (gateway MAC changed) is sent only after the delay, so
// the DNS check, which starts 2 s after the same trigger, sees the network
// before the probe disturbs it. Kicks inside the gap send nothing.
func TestProbeLoopDelaysKick(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sent := make(chan time.Time, 8)
	kick := make(chan struct{}, 1)
	tick := make(chan time.Time)
	const delay = 300 * time.Millisecond
	done := make(chan struct{})
	gate := &probeGate{gap: 200 * time.Millisecond}
	go func() {
		defer close(done)
		probeLoop(ctx, func() { sent <- time.Now() }, kick, tick, gate, delay)
	}()
	next := func(within time.Duration) (time.Time, bool) {
		select {
		case at := <-sent:
			return at, true
		case <-time.After(within):
			return time.Time{}, false
		}
	}
	if _, ok := next(time.Second); !ok {
		t.Fatal("no probe at start")
	}
	// a kick inside the gap sends nothing
	kick <- struct{}{}
	if _, ok := next(100 * time.Millisecond); ok {
		t.Fatal("kick inside the gap sent a probe")
	}
	// after the gap: the probe comes, but not before the delay
	time.Sleep(150 * time.Millisecond)
	kicked := time.Now()
	kick <- struct{}{}
	at, ok := next(2 * time.Second)
	if !ok {
		t.Fatal("no probe after the kick")
	}
	if d := at.Sub(kicked); d < delay {
		t.Fatalf("probe %v after the kick, want at least %v", d, delay)
	}
	// the periodic probe is not delayed
	ticked := time.Now()
	tick <- ticked
	at, ok = next(time.Second)
	if !ok || at.Sub(ticked) > delay/2 {
		t.Fatalf("periodic probe delayed: %v %v", ok, at.Sub(ticked))
	}
	// ending during the wait: no probe, the loop returns
	time.Sleep(250 * time.Millisecond)
	kick <- struct{}{}
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("loop did not end")
	}
	if _, ok := next(delay + 100*time.Millisecond); ok {
		t.Fatal("probe sent after the end")
	}
}
