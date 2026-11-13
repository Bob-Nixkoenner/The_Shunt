package defense

import (
	"net/netip"
	"time"
)

// Trust steps of an IgnoreEntry.Level. "" (TrustFull) ignores the source
// completely; the other two keep it visible but quiet.
const (
	TrustFull  = ""
	TrustKnown = "known"
	TrustTest  = "test"
)

// TestSeconds is how long the "test" step lasts when the UI sets it.
const TestSeconds = 3600

// TestMaxSeconds caps a "test" entry: an end time further away (a hand-edited
// config, a wrong clock) counts as this long from when the list was loaded,
// so a test entry cannot become a hidden "never block" for good.
const TestMaxSeconds = 24 * 3600

// KnownHeatCap is the highest heat share events of "known" sources can cause.
const KnownHeatCap = 50

// Trust returns the step ("known", "test" or "") of traffic from a to local
// port (0 = unknown) at time now. Expired test entries give "".
func (s *IgnoreSet) Trust(a netip.Addr, port int, now time.Time) string {
	return s.trust(a, port, now, false)
}

// TrustAny is Trust for any port: used for blocks, which carry no port.
func (s *IgnoreSet) TrustAny(a netip.Addr, now time.Time) string {
	return s.trust(a, 0, now, true)
}

func (s *IgnoreSet) trust(a netip.Addr, port int, now time.Time, anyPort bool) string {
	a = a.Unmap()
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := ""
	for _, r := range s.rules {
		if r.level == TrustFull || !r.p.Contains(a) {
			continue
		}
		if !anyPort && r.ports != nil && !r.ports[port] {
			continue
		}
		if r.level == TrustTest {
			if !now.Before(r.until) {
				continue
			}
			return TrustTest
		}
		out = TrustKnown
	}
	return out
}
