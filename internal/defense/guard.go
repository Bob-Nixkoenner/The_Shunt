package defense

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"time"
)

// The defense reads bytes from strangers in many goroutines. A panic in any
// goroutine ends the whole process, and with it the tunnel control and the
// kill switch. Guard and GuardLoop turn such a bug into a log line: it costs
// one connection or one sensor round, not the daemon.

var faults atomic.Uint64

// Faults is the number of panics caught since start.
func Faults() uint64 { return faults.Load() }

// Guard runs f. A panic in f is caught, counted and logged (the first ten in
// full, then every hundredth, so a peer who can trigger one cannot fill the
// log). It reports whether f panicked.
func Guard(log *slog.Logger, where string, f func()) (panicked bool) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		panicked = true
		n := faults.Add(1)
		if n > 10 && n%100 != 0 {
			return
		}
		if log == nil {
			log = slog.Default()
		}
		log.Error("defense: internal error caught (please report)", "where", where,
			"err", clip(fmt.Sprint(r), 200), "count", n, "stack", clip(string(debug.Stack()), 2000))
	}()
	f()
	return false
}

// guardRestarts is how often GuardLoop starts a crashed loop again.
const guardRestarts = 5

// GuardLoop runs a long-lived f (a sensor, a reader). When f panics it is
// started again after a pause (1 s, doubling) at most guardRestarts times
// while ctx lives; a normal return ends it. pause may be nil (tests set it).
func GuardLoop(ctx context.Context, log *slog.Logger, where string, f func()) {
	guardLoop(ctx, log, where, time.Second, f)
}

func guardLoop(ctx context.Context, log *slog.Logger, where string, pause time.Duration, f func()) {
	for try := 0; ; try++ {
		if !Guard(log, where, f) || ctx.Err() != nil {
			return
		}
		if try >= guardRestarts {
			if log == nil {
				log = slog.Default()
			}
			log.Error("defense: giving up on a part that keeps failing (off until the next restart or network change)", "where", where)
			return
		}
		t := time.NewTimer(pause << try)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// clip keeps printable text of at most n bytes (panic values can carry bytes
// from a peer).
func clip(s string, n int) string {
	if len(s) > n {
		s = s[:n]
	}
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return ' '
		}
		if r < 0x20 || r == 0x7f || r == 0xfffd {
			return -1
		}
		return r
	}, s)
}
