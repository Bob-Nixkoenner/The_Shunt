// Package override holds the two emergency switches, the same on every
// platform: panic (block everything) and a short pass (everything goes
// direct, past all tunnels and blocks, for a few minutes, then back by
// itself). Panic always wins.
package override

import (
	"sync"
	"time"
)

// MaxPass is the longest pass; a pass is never open-ended.
const MaxPass = 60 * time.Minute

// State is safe for concurrent use; the zero value is "nothing active".
type State struct {
	mu        sync.Mutex
	panic     bool
	passUntil time.Time
}

// SetPanic switches panic mode.
func (s *State) SetPanic(on bool) {
	s.mu.Lock()
	s.panic = on
	s.mu.Unlock()
}

// Pass lets everything through for d (clamped to 1 minute .. MaxPass);
// d <= 0 ends a pass. Returns the end time (zero when ended).
func (s *State) Pass(d time.Duration, now time.Time) time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d <= 0 {
		s.passUntil = time.Time{}
		return s.passUntil
	}
	s.passUntil = now.Add(min(max(d, time.Minute), MaxPass))
	return s.passUntil
}

// Route turns the normal route of a connection into the one to use now.
func (s *State) Route(normal string, now time.Time) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.panic:
		return "block"
	case now.Before(s.passUntil):
		return "direct"
	}
	return normal
}

// Status is what UIs show.
type Status struct {
	Panic     bool  `json:"panic"`
	PassUntil int64 `json:"pass_until,omitempty"` // unix seconds while a pass runs
	PassLeft  int64 `json:"pass_left,omitempty"`  // seconds
}

// Status reports the switches at now.
func (s *State) Status(now time.Time) Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Status{Panic: s.panic}
	if now.Before(s.passUntil) {
		st.PassUntil, st.PassLeft = s.passUntil.Unix(), int64(s.passUntil.Sub(now).Seconds()+0.5)
	}
	return st
}

// Passing reports whether a pass runs at now (expired passes end by themselves).
func (s *State) Passing(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return now.Before(s.passUntil)
}
