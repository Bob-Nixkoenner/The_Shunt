package defense

import (
	"net/netip"
	"sort"
	"sync"
	"time"
)

// Bans is the table of blocked sources with expiry. The Linux side hooks
// OnBan/OnUnban to add and remove firewall entries. Callbacks run without
// the table lock held.
type Bans struct {
	mu      sync.Mutex
	m       map[string]Ban
	Max     int // hard cap on the table (0 = DefaultMaxBans); the soonest-expiring entry makes room
	now     func() time.Time
	OnBan   func(Ban)
	OnUnban func(Ban)
}

// DefaultMaxBans is the hard cap of the ban table: a flood from many sources
// (masscan, botnet) must not grow memory or the firewall set without limit.
const DefaultMaxBans = 4096

// NewBans returns an empty table.
func NewBans() *Bans { return &Bans{m: map[string]Ban{}, now: time.Now} }

// Add blocks src for d. It returns the ban and true if it is new; an existing
// ban is only extended.
func (b *Bans) Add(src string, reason Kind, d time.Duration) (Ban, bool) {
	return b.AddLevel(src, reason, d, false, 1)
}

// permanentHorizon is the Expires of a permanent ban (the firewall entry gets
// this timeout; the entry is also kept by Prune until lifted by hand).
const permanentHorizon = 10 * 365 * 24 * time.Hour

// AddLevel is Add with an escalation level and the option permanent. Beyond
// MaxPermanentBans permanent entries a permanent request becomes 24 h.
func (b *Bans) AddLevel(src string, reason Kind, d time.Duration, permanent bool, level int) (Ban, bool) {
	b.mu.Lock()
	now := b.now()
	if permanent {
		n := 0
		for k, v := range b.m {
			if v.Permanent && k != src {
				n++
			}
		}
		if n >= MaxPermanentBans {
			permanent, d = false, DefaultBanSeconds2*time.Second
		} else {
			d = permanentHorizon
		}
	}
	ban, exists := b.m[src]
	if exists {
		if e := now.Add(d); e.After(ban.Expires) {
			ban.Expires = e
			ban.Permanent = ban.Permanent || permanent
			if level > ban.Level {
				ban.Level = level
			}
			b.m[src] = ban
		}
		b.mu.Unlock()
		return ban, false
	}
	max := b.Max
	if max <= 0 {
		max = DefaultMaxBans
	}
	var evicted []Ban
	for len(b.m) >= max {
		var oldest string
		var at time.Time
		for k, v := range b.m {
			if oldest == "" || v.Expires.Before(at) || (v.Expires.Equal(at) && k < oldest) {
				oldest, at = k, v.Expires
			}
		}
		evicted = append(evicted, b.m[oldest])
		delete(b.m, oldest)
	}
	ban = Ban{Src: src, Reason: reason, Since: now, Expires: now.Add(d), Permanent: permanent, Level: level}
	b.m[src] = ban
	cb, un := b.OnBan, b.OnUnban
	b.mu.Unlock()
	if un != nil {
		for _, v := range evicted {
			un(v)
		}
	}
	if cb != nil {
		cb(ban)
	}
	return ban, true
}

// Has reports whether src is blocked now.
func (b *Bans) Has(src string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	ban, ok := b.m[src]
	return ok && b.now().Before(ban.Expires)
}

// Remove lifts one ban ("" = all) and returns the lifted ones.
func (b *Bans) Remove(src string) []Ban {
	b.mu.Lock()
	var gone []Ban
	for k, v := range b.m {
		if src == "" || k == src {
			gone = append(gone, v)
			delete(b.m, k)
		}
	}
	cb := b.OnUnban
	b.mu.Unlock()
	if cb != nil {
		for _, v := range gone {
			cb(v)
		}
	}
	return gone
}

// Prune lifts expired bans and returns them.
func (b *Bans) Prune() []Ban {
	b.mu.Lock()
	now := b.now()
	var gone []Ban
	for k, v := range b.m {
		if !v.Permanent && !now.Before(v.Expires) {
			gone = append(gone, v)
			delete(b.m, k)
		}
	}
	cb := b.OnUnban
	b.mu.Unlock()
	if cb != nil {
		for _, v := range gone {
			cb(v)
		}
	}
	return gone
}

// List returns the active bans sorted by Src (never nil).
func (b *Bans) List() []Ban {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]Ban, 0, len(b.m))
	for _, v := range b.m {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Src < out[j].Src })
	return out
}

// RangeOf is the block range of a: /24 for IPv4, /64 for IPv6.
func RangeOf(a netip.Addr) netip.Prefix {
	a = a.Unmap()
	bits := 64
	if a.Is4() {
		bits = 24
	}
	p, _ := a.Prefix(bits)
	return p
}

// Covered reports whether a range ban (CIDR entry) covers a.
func (b *Bans) Covered(a netip.Addr) bool {
	r := RangeOf(a).String()
	b.mu.Lock()
	defer b.mu.Unlock()
	ban, ok := b.m[r]
	return ok && b.now().Before(ban.Expires)
}

// InRange lists the single-address bans inside p.
func (b *Bans) InRange(p netip.Prefix) []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []string
	for k := range b.m {
		if a, err := netip.ParseAddr(k); err == nil && p.Contains(a) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// Len is the number of entries (single addresses and ranges).
func (b *Bans) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.m)
}
