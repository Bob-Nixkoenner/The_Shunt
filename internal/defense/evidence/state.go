package evidence

import (
	"fmt"
	"sync"
	"time"
)

// JumpThreshold is the difference between wall clock and monotonic clock
// that is written down as a clock jump (a manipulated time source is an
// attack of its own, and it weakens the time stamps of the evidence).
const JumpThreshold = 5 * time.Second

// StateWatch writes the facts a reader needs to judge the log: whether the
// system clock is synchronised, jumps of the clock, and when the network
// was joined (its class, never its name). Read only; it changes nothing on
// the system.
type StateWatch struct {
	Log *Log
	// Synced reports the clock sync state: synced, and whether the system
	// can tell at all.
	Synced func() (synced, known bool)
	Now    func() time.Time

	mu     sync.Mutex
	wall   time.Time // last reading, with its monotonic part
	last   string    // last sync line written
	class  string
	net    string
	joined time.Time
}

func (w *StateWatch) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now()
}

// SetNet records the network class and the moment it was joined.
func (w *StateWatch) SetNet(class string, joined time.Time) {
	w.mu.Lock()
	w.class, w.joined = class, joined
	w.mu.Unlock()
}

// SetNetID records the short network label (see defense.NetID) for the state
// line at the top of new files.
func (w *StateWatch) SetNetID(id string) {
	w.mu.Lock()
	w.net = id
	w.mu.Unlock()
}

func (w *StateWatch) syncDetail() string {
	if w.Synced == nil {
		return "ntp_synchronized=unknown"
	}
	s, known := w.Synced()
	switch {
	case !known:
		return "ntp_synchronized=unknown"
	case s:
		return "ntp_synchronized=yes"
	}
	return "ntp_synchronized=no"
}

// Preamble is the Log's Options.Preamble: the state lines at the top of
// every new file.
func (w *StateWatch) Preamble() []Input {
	w.mu.Lock()
	defer w.mu.Unlock()
	d := w.syncDetail()
	w.last = d
	out := []Input{{Kind: "state_clock", Severity: "info", Detail: d}}
	if !w.joined.IsZero() {
		out = append(out, Input{Kind: "state_net", Severity: "info", Detail: fmt.Sprintf("class=%s joined=%s%s", w.class, w.joined.UTC().Format(time.RFC3339), netSuffix(w.net))})
	}
	return out
}

// Check looks for a clock jump and a change of the sync state. Call it
// every 30 seconds or so.
func (w *StateWatch) Check() { w.CheckAt(w.now(), 0, false) }

// CheckAt is Check with an explicit reading: wall is the current time and,
// when haveMono is true, mono the elapsed monotonic time since the last
// call (tests); otherwise both come from the time package.
func (w *StateWatch) CheckAt(wall time.Time, mono time.Duration, haveMono bool) {
	w.mu.Lock()
	prev := w.wall
	w.wall = wall
	d := w.syncDetail()
	changed := d != w.last && w.last != ""
	if w.last == "" {
		w.last = d
	}
	if changed {
		w.last = d
	}
	w.mu.Unlock()
	if w.Log == nil {
		return
	}
	if changed {
		_, _ = w.Log.Append(Input{Kind: "state_clock", Severity: "low", Detail: d + " (changed)"})
	}
	if prev.IsZero() {
		return
	}
	var diff time.Duration
	if haveMono {
		diff = wall.Round(0).Sub(prev.Round(0)) - mono
	} else {
		diff = wall.Round(0).Sub(prev.Round(0)) - wall.Sub(prev)
	}
	if diff > JumpThreshold || diff < -JumpThreshold {
		_, _ = w.Log.Append(Input{Kind: "clock_jump", Severity: "medium", Detail: fmt.Sprintf("system clock moved %+.1fs against the monotonic clock", diff.Seconds())})
	}
}

func netSuffix(id string) string {
	if id == "" {
		return ""
	}
	return " net=" + id
}
