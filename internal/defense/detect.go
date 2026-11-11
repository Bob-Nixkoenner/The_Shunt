package defense

import (
	"net/netip"
	"sync"
	"time"
)

// NeverSet is the allow-list of addresses that are never blocked: the
// configured entries plus the automatic ones (gateway, DNS, captive portal).
type NeverSet struct {
	mu   sync.RWMutex
	cfg  []netip.Prefix
	auto []netip.Prefix
}

// ParsePrefixes parses addresses and CIDRs, skipping invalid entries.
func ParsePrefixes(in []string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range in {
		if p, ok := parsePrefix(s); ok {
			out = append(out, p)
		}
	}
	return out
}

func parsePrefix(s string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}

// SetConfig replaces the configured entries.
func (n *NeverSet) SetConfig(p []netip.Prefix) { n.mu.Lock(); n.cfg = p; n.mu.Unlock() }

// SetAuto replaces the automatic entries.
func (n *NeverSet) SetAuto(p []netip.Prefix) { n.mu.Lock(); n.auto = p; n.mu.Unlock() }

// Contains reports whether a is on the list.
func (n *NeverSet) Contains(a netip.Addr) bool {
	a = a.Unmap()
	n.mu.RLock()
	defer n.mu.RUnlock()
	for _, l := range [][]netip.Prefix{n.cfg, n.auto} {
		for _, p := range l {
			if p.Contains(a) {
				return true
			}
		}
	}
	return false
}

// DetectConfig holds the thresholds.
type DetectConfig struct {
	Window     time.Duration // sliding window (default 60 s)
	ScanPorts  int           // distinct ports from one source (default 6)
	BruteConns int           // failed connections from one source (default 10)
	MaxSources int           // memory cap (default 4096)
}

func (c DetectConfig) withDefaults() DetectConfig {
	if c.Window <= 0 {
		c.Window = time.Minute
	}
	if c.ScanPorts <= 0 {
		c.ScanPorts = 6
	}
	if c.BruteConns <= 0 {
		c.BruteConns = 10
	}
	if c.MaxSources <= 0 {
		c.MaxSources = 4096
	}
	return c
}

// Finding is what the detector found about one source.
type Finding struct {
	Kind   Kind
	Src    netip.Addr
	Detail string
}

type srcState struct {
	ports     map[int]time.Time
	fails     []time.Time
	scanFired time.Time
	bfFired   time.Time
	last      time.Time
}

// Detector spots port scans and brute force from observed connections.
type Detector struct {
	mu      sync.Mutex
	cfg     DetectConfig
	never   *NeverSet
	src     map[netip.Addr]*srcState
	now     func() time.Time
	OnFound func(Finding)
}

// NewDetector returns a detector; never may be nil.
func NewDetector(cfg DetectConfig, never *NeverSet) *Detector {
	if never == nil {
		never = &NeverSet{}
	}
	return &Detector{cfg: cfg.withDefaults(), never: never, src: map[netip.Addr]*srcState{}, now: time.Now}
}

// SetConfig changes the thresholds.
func (d *Detector) SetConfig(c DetectConfig) { d.mu.Lock(); d.cfg = c.withDefaults(); d.mu.Unlock() }

// Observe records one connection attempt from src to a local port. ok=false
// means it failed or hit a closed/decoy port. Addresses on the never-list
// are ignored. A finding fires at most once per window and source.
func (d *Detector) Observe(src netip.Addr, port int, proto string, ok bool) {
	src = src.Unmap()
	if !src.IsValid() || d.never.Contains(src) {
		return
	}
	var found []Finding
	d.mu.Lock()
	now := d.now()
	w := d.cfg.Window
	st := d.src[src]
	if st == nil {
		if len(d.src) >= d.cfg.MaxSources {
			d.evict(now)
			if len(d.src) >= d.cfg.MaxSources {
				d.mu.Unlock()
				return
			}
		}
		st = &srcState{ports: map[int]time.Time{}}
		d.src[src] = st
	}
	st.last = now
	st.ports[port] = now
	for p, t := range st.ports {
		if now.Sub(t) > w {
			delete(st.ports, p)
		}
	}
	if len(st.ports) >= d.cfg.ScanPorts && now.Sub(st.scanFired) > w {
		st.scanFired = now
		found = append(found, Finding{KindScan, src, "distinct ports in window: " + itoa(len(st.ports)) + " (" + proto + ")"})
	}
	if !ok {
		st.fails = append(st.fails, now)
		i := 0
		for i < len(st.fails) && now.Sub(st.fails[i]) > w {
			i++
		}
		st.fails = st.fails[i:]
		if len(st.fails) >= d.cfg.BruteConns && now.Sub(st.bfFired) > w {
			st.bfFired = now
			found = append(found, Finding{KindBruteForce, src, "failed attempts in window: " + itoa(len(st.fails))})
		}
	}
	cb := d.OnFound
	d.mu.Unlock()
	if cb != nil {
		for _, f := range found {
			cb(f)
		}
	}
}

func (d *Detector) evict(now time.Time) {
	for a, s := range d.src {
		if now.Sub(s.last) > d.cfg.Window {
			delete(d.src, a)
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
