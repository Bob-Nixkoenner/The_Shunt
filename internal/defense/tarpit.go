package defense

import (
	"context"
	"net"
	"sync/atomic"
	"time"
)

// Tarpit holds hostile connections open and feeds them one byte every few
// seconds (the same idea as Endlessh; own implementation).
type Tarpit struct {
	Interval time.Duration // gap between bytes (default 7 s)
	MaxHold  time.Duration // longest a peer is kept (default 10 min)
	MaxConns int           // simultaneous traps (default 32)
	active   atomic.Int32
}

// Active returns how many connections are held now.
func (t *Tarpit) Active() int { return int(t.active.Load()) }

// TryHold takes over conn if a slot is free and returns true; the
// connection is closed when the hold ends. With no free slot it returns false
// and leaves conn alone.
func (t *Tarpit) TryHold(ctx context.Context, conn net.Conn, done func(held time.Duration)) bool {
	max := t.MaxConns
	if max <= 0 {
		max = 32
	}
	if int(t.active.Add(1)) > max {
		t.active.Add(-1)
		return false
	}
	go func() {
		start := time.Now()
		defer t.active.Add(-1)
		defer conn.Close()
		t.hold(ctx, conn)
		if done != nil {
			done(time.Since(start))
		}
	}()
	return true
}

func (t *Tarpit) hold(ctx context.Context, conn net.Conn) {
	iv := t.Interval
	if iv <= 0 {
		iv = 7 * time.Second
	}
	maxHold := t.MaxHold
	if maxHold <= 0 {
		maxHold = 10 * time.Minute
	}
	deadline := time.NewTimer(maxHold)
	defer deadline.Stop()
	tick := time.NewTicker(iv)
	defer tick.Stop()
	// Notice when the peer hangs up.
	gone := make(chan struct{})
	go func() {
		buf := make([]byte, 256)
		for {
			if _, err := conn.Read(buf); err != nil {
				close(gone)
				return
			}
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case <-deadline.C:
			return
		case <-gone:
			return
		case <-tick.C:
			_ = conn.SetWriteDeadline(time.Now().Add(iv))
			if _, err := conn.Write([]byte{'x'}); err != nil {
				return
			}
		}
	}
}
