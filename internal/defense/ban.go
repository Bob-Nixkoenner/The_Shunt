package defense

import (
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
	now     func() time.Time
	OnBan   func(Ban)
	OnUnban func(Ban)
}

// NewBans returns an empty table.
func NewBans() *Bans { return &Bans{m: map[string]Ban{}, now: time.Now} }

// Add blocks src for d. It returns the ban and true if it is new; an existing
// ban is only extended.
func (b *Bans) Add(src string, reason Kind, d time.Duration) (Ban, bool) {
	b.mu.Lock()
	now := b.now()
	ban, exists := b.m[src]
	if exists {
		if e := now.Add(d); e.After(ban.Expires) {
			ban.Expires = e
			b.m[src] = ban
		}
		b.mu.Unlock()
		return ban, false
	}
	ban = Ban{Src: src, Reason: reason, Since: now, Expires: now.Add(d)}
	b.m[src] = ban
	cb := b.OnBan
	b.mu.Unlock()
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
		if !now.Before(v.Expires) {
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
