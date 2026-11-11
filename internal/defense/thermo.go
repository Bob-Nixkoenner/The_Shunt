package defense

import (
	"math"
	"sync"
	"time"
)

// HeatHalfLife is how fast the gauge cools down.
const HeatHalfLife = 10 * time.Minute

// heatScale: raw points (after class factor) that give about 63 heat.
const heatScale = 40.0

// ClassFactor scales how much events count in a network class.
func ClassFactor(c Class) float64 {
	switch c.Normalize() {
	case ClassTrusted:
		return 0.4
	case ClassManaged:
		return 0.7
	}
	return 1.0
}

// eventPoints is the raw weight of one event.
func eventPoints(k Kind, s Severity) float64 {
	switch k {
	case KindNetEnter, KindBan, KindUnban:
		return 0
	}
	var p float64
	switch s {
	case SevLow:
		p = 2
	case SevMedium:
		p = 8
	case SevHigh:
		p = 20
	default:
		return 0
	}
	switch k {
	case KindCowrie:
		p *= 1.5
	case KindARP, KindRogueDHCP, KindDHCPOption, KindRogueRA, KindDNSHijack, KindEvilTwin, KindTLS:
		p *= 2
	}
	return p
}

// Thermo is the heat gauge: events add points, points fade exponentially,
// and the shown value saturates smoothly below 100.
type Thermo struct {
	mu     sync.Mutex
	raw    float64
	at     time.Time
	class  Class
	key    string
	counts map[Kind]int
	now    func() time.Time
}

// NewThermo returns a gauge for a public network.
func NewThermo() *Thermo {
	return &Thermo{class: ClassPublic, counts: map[Kind]int{}, now: time.Now}
}

func (t *Thermo) decay(now time.Time) {
	if !t.at.IsZero() && now.After(t.at) {
		t.raw *= math.Exp2(-float64(now.Sub(t.at)) / float64(HeatHalfLife))
	}
	t.at = now
}

// SetNetwork sets the class. A new key resets the per-kind counters.
func (t *Thermo) SetNetwork(key string, class Class) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.decay(t.now())
	t.class = class.Normalize()
	if key != t.key {
		t.key = key
		t.counts = map[Kind]int{}
		t.raw = 0 // a new network starts cool (its report keeps its own peak)
	}
}

// Add counts the event and raises the heat.
func (t *Thermo) Add(ev Event) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.decay(t.now())
	t.counts[ev.Kind]++
	t.raw += eventPoints(ev.Kind, ev.Severity) * ClassFactor(t.class)
}

// Heat returns 0-100.
func (t *Thermo) Heat() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.decay(t.now())
	h := int(math.Round(100 * (1 - math.Exp(-t.raw/heatScale))))
	return max(0, min(100, h))
}

// Counts returns a copy of the per-kind counters since the network was joined.
func (t *Thermo) Counts() map[Kind]int {
	t.mu.Lock()
	defer t.mu.Unlock()
	c := make(map[Kind]int, len(t.counts))
	for k, v := range t.counts {
		c[k] = v
	}
	return c
}
