package defense

import (
	"sort"
	"sync"
	"time"
)

// BeaconScore rates how regular the gaps between events are: 0 (irregular)
// to 1 (clockwork). It needs at least minEvents timestamps (min 5) and a
// median gap of one second or more. Jitter is the median absolute deviation
// relative to the median gap; 30 % or more scores 0.
func BeaconScore(times []time.Time, minEvents int) (score float64, interval time.Duration) {
	if minEvents < 5 {
		minEvents = 5
	}
	if len(times) < minEvents {
		return 0, 0
	}
	ts := append([]time.Time(nil), times...)
	sort.Slice(ts, func(i, j int) bool { return ts[i].Before(ts[j]) })
	gaps := make([]float64, 0, len(ts)-1)
	for i := 1; i < len(ts); i++ {
		gaps = append(gaps, ts[i].Sub(ts[i-1]).Seconds())
	}
	med := median(gaps)
	if med < 1 {
		return 0, 0
	}
	dev := make([]float64, len(gaps))
	for i, g := range gaps {
		if g > med {
			dev[i] = g - med
		} else {
			dev[i] = med - g
		}
	}
	jitter := median(dev) / med
	s := 1 - jitter/0.3
	if s < 0 {
		s = 0
	}
	return s, time.Duration(med * float64(time.Second))
}

func median(v []float64) float64 {
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	n := len(s)
	if n == 0 {
		return 0
	}
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

// BeaconTracker keeps recent timestamps per target (a destination key).
type BeaconTracker struct {
	mu         sync.Mutex
	m          map[string][]time.Time
	MaxTargets int // default 1024
	Keep       int // timestamps per target, default 64
}

// NewBeaconTracker returns an empty tracker.
func NewBeaconTracker() *BeaconTracker {
	return &BeaconTracker{m: map[string][]time.Time{}, MaxTargets: 1024, Keep: 64}
}

// Add records a contact with target and returns its current score.
func (b *BeaconTracker) Add(target string, t time.Time, minEvents int) (float64, time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	l, ok := b.m[target]
	if !ok && len(b.m) >= b.MaxTargets {
		// make room: targets not contacted for two hours are stale
		for k, v := range b.m {
			if len(v) == 0 || t.Sub(v[len(v)-1]) > 2*time.Hour {
				delete(b.m, k)
			}
		}
		if len(b.m) >= b.MaxTargets {
			return 0, 0
		}
	}
	l = append(l, t)
	if len(l) > b.Keep {
		l = l[len(l)-b.Keep:]
	}
	b.m[target] = l
	return BeaconScore(l, minEvents)
}

// Forget drops everything (new network).
func (b *BeaconTracker) Forget() {
	b.mu.Lock()
	b.m = map[string][]time.Time{}
	b.mu.Unlock()
}
