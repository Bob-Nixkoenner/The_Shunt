package defense

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestGuardCatchesAndCounts(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	before := Faults()
	if Guard(log, "ok", func() {}) {
		t.Fatal("no panic reported as one")
	}
	if !Guard(log, "test part", func() { var b []byte; _ = b[3] }) {
		t.Fatal("panic not reported")
	}
	if Faults() != before+1 {
		t.Fatalf("faults %d -> %d", before, Faults())
	}
	out := buf.String()
	if !strings.Contains(out, "internal error caught") || !strings.Contains(out, "test part") || !strings.Contains(out, "index out of range") {
		t.Fatalf("log: %s", out)
	}
	// a panic value with control bytes from a peer is cleaned
	buf.Reset()
	Guard(log, "x", func() { panic("a\x1b[31m\r\nb") })
	if strings.Contains(buf.String(), "\x1b") {
		t.Fatalf("control bytes in log: %q", buf.String())
	}
}

func TestGuardLoopRestartsAndGivesUp(t *testing.T) {
	log := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	n := 0
	guardLoop(context.Background(), log, "flaky", time.Millisecond, func() {
		n++
		if n < 3 {
			panic("boom")
		}
	})
	if n != 3 {
		t.Fatalf("ran %d times, want 3 (two restarts, then a normal end)", n)
	}
	n = 0
	guardLoop(context.Background(), log, "broken", time.Microsecond, func() { n++; panic("always") })
	if n != guardRestarts+1 {
		t.Fatalf("ran %d times, want %d", n, guardRestarts+1)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	n = 0
	guardLoop(ctx, log, "stopped", time.Hour, func() { n++; panic("x") })
	if n != 1 {
		t.Fatalf("restarted after cancel: %d", n)
	}
}

// A bug in a decoy handler (here: the hit callback panics) closes that one
// connection; the decoy keeps answering the next one.
func TestDecoyHandlerPanicIsContained(t *testing.T) {
	pm := &portMap{real: map[int]int{}}
	var calls atomic.Int32
	d := NewDecoys(pm.listen, func(Hit) {
		if calls.Add(1) == 1 {
			panic("bug in the handler")
		}
	})
	d.Log = slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	d.Start([]int{80}, DecoyOptions{})
	defer d.Stop()
	before := Faults()
	c := pm.dial(t, 80)
	buf := make([]byte, 64)
	if _, err := c.Read(buf); err == nil {
		t.Fatal("first connection got an answer after the panic")
	}
	c.Close()
	if Faults() != before+1 {
		t.Fatalf("faults %d -> %d", before, Faults())
	}
	c2 := pm.dial(t, 80)
	defer c2.Close()
	n, err := c2.Read(buf)
	if err != nil || !strings.HasPrefix(string(buf[:n]), "HTTP/1.1") {
		t.Fatalf("decoy dead after a handler panic: %v %q", err, buf[:n])
	}
	// the slot of the crashed handler was given back
	c2.Close()
	deadline := time.Now().Add(2 * time.Second)
	for {
		d.srcMu.Lock()
		left := len(d.perSrc)
		d.srcMu.Unlock()
		if left == 0 && len(d.sem) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("slots not released: sources %d, handlers %d", left, len(d.sem))
		}
		time.Sleep(10 * time.Millisecond)
	}
}
