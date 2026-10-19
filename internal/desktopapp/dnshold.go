package desktopapp

import "time"

// DNSNotifyAfter: a route's DNS must have been failing this long before the
// tray tells you (the daemon already waits for several failed queries; a lossy
// tunnel makes it flicker for ten seconds at a time, which is just noise).
const DNSNotifyAfter = 60 * time.Second

// DNSHold hides DNS failures that are younger than a limit.
type DNSHold struct{ since map[string]time.Time }

// Filter returns the routes of failing that have been failing for at least
// after (failing is the daemon's report: route -> last error).
func (h *DNSHold) Filter(failing map[string]string, now time.Time, after time.Duration) map[string]string {
	if h.since == nil {
		h.since = map[string]time.Time{}
	}
	for r := range h.since {
		if _, ok := failing[r]; !ok {
			delete(h.since, r)
		}
	}
	out := map[string]string{}
	for r, e := range failing {
		t, ok := h.since[r]
		if !ok {
			h.since[r], t = now, now
		}
		if now.Sub(t) >= after {
			out[r] = e
		}
	}
	return out
}
