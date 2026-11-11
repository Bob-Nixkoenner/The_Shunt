package defense

import (
	"sync"
	"time"
)

// MaxEventsPerCall is the most events Events returns at once.
const MaxEventsPerCall = 200

// Ring keeps the newest events in memory (never written to disk).
type Ring struct {
	mu   sync.Mutex
	buf  []Event // oldest first
	cap  int
	last uint64
	now  func() time.Time
}

// NewRing makes a ring that keeps up to capacity events (min 1).
func NewRing(capacity int) *Ring {
	if capacity < 1 {
		capacity = 1
	}
	return &Ring{cap: capacity, now: time.Now}
}

// Add stores ev, assigns Seq (from 1) and fills a zero Time. It returns the stored event.
func (r *Ring) Add(ev Event) Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.last++
	ev.Seq = r.last
	if ev.Time.IsZero() {
		ev.Time = r.now()
	}
	if len(r.buf) == r.cap {
		copy(r.buf, r.buf[1:])
		r.buf = r.buf[:len(r.buf)-1]
	}
	r.buf = append(r.buf, ev)
	return ev
}

// LastSeq is the Seq of the newest event (0 if none yet).
func (r *Ring) LastSeq() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.last
}

// MaxSourceEvents is the most events EventsFor returns.
const MaxSourceEvents = 500

// EventsFor returns the newest events whose Src is src, oldest first. The
// last_seq of the answer is the ring's, so a caller can keep polling.
func (r *Ring) EventsFor(src string) EventsResponse {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []Event{}
	for i := len(r.buf) - 1; i >= 0 && len(out) < MaxSourceEvents; i-- {
		if r.buf[i].Src == src {
			out = append(out, r.buf[i])
		}
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return EventsResponse{Events: out, LastSeq: r.last}
}

// Events returns events with Seq > since, oldest first, at most MaxEventsPerCall.
func (r *Ring) Events(since uint64) EventsResponse {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []Event{}
	for _, e := range r.buf {
		if e.Seq > since {
			out = append(out, e)
			if len(out) == MaxEventsPerCall {
				break
			}
		}
	}
	return EventsResponse{Events: out, LastSeq: r.last}
}
