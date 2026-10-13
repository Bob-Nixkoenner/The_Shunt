package dnsproxy

import (
	"net/netip"
	"sync"
	"time"
)

// SetWriter adds addresses with a timeout to an nftables set.
type SetWriter interface {
	Add(set string, addrs []netip.Addr, timeout time.Duration) error
}

// pairSets keeps domain-rule addresses in the kernel for as long as clients
// may use them.
//
// The invariant: an address handed to a client with TTL t stays in the
// rule's set for at least t (+grace). Otherwise the client's cached answer
// would outlive the set entry and its next connection would silently take
// the default route.
//
// nftables cannot extend the timeout of an existing element, and deleting
// and re-adding opens a window. So every rule has two sets per family
// ("a" and "b") matched by the same verdict: to extend an address we add
// it to whichever set does not hold it. Clients get their TTL capped to
// the remaining lifetime of the longest-living copy.
type pairSets struct {
	w   SetWriter
	now func() time.Time

	mu sync.Mutex
	// expiry[base][addr] = expiry in set a and set b
	expiry map[string]map[netip.Addr][2]time.Time
}

const (
	minLifetime = 5 * time.Minute
	maxLifetime = 2 * time.Hour
	grace       = 30 * time.Second
)

func newPairSets(w SetWriter) *pairSets {
	return &pairSets{w: w, now: time.Now, expiry: map[string]map[netip.Addr][2]time.Time{}}
}

// ensure makes sure every address lives at least ttl+grace in set base
// ("…a"/"…b") and returns the TTL that is safe to give to the client.
func (p *pairSets) ensure(base string, addrs []netip.Addr, ttl time.Duration) (time.Duration, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	m := p.expiry[base]
	if m == nil {
		m = map[netip.Addr][2]time.Time{}
		p.expiry[base] = m
	}
	want := now.Add(ttl + grace)
	life := ttl + grace
	if life < minLifetime {
		life = minLifetime
	}
	if life > maxLifetime {
		life = maxLifetime
	}
	add := [2][]netip.Addr{}
	safe := ttl
	for _, a := range addrs {
		e := m[a]
		if e[0].After(want) || e[1].After(want) {
			continue
		}
		// pick the slot that is free (expired) or expires first
		slot := 0
		if e[1].Before(e[0]) {
			slot = 1
		}
		if e[slot].After(now) {
			// both copies alive but too short: cap the client's TTL to the
			// longer one; the shorter slot frees up before the client asks again
			longest := e[0]
			if e[1].After(longest) {
				longest = e[1]
			}
			if rem := longest.Sub(now) - grace; rem < safe {
				safe = max(rem, 0)
			}
			continue
		}
		add[slot] = append(add[slot], a)
		e[slot] = now.Add(life)
		m[a] = e
	}
	for slot, as := range add {
		if len(as) == 0 {
			continue
		}
		if err := p.w.Add(base+string(rune('a'+slot)), as, life); err != nil {
			return 0, err
		}
	}
	return safe, nil
}

// replay re-adds all live entries, e.g. after the ruleset (and with it the
// sets) was replaced. keep tells which set bases still exist.
func (p *pairSets) replay(keep map[string]bool) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	for base, m := range p.expiry {
		if !keep[base] {
			delete(p.expiry, base)
			continue
		}
		for slot := 0; slot < 2; slot++ {
			// group by remaining lifetime (rounded) to batch netlink calls
			batches := map[time.Duration][]netip.Addr{}
			for a, e := range m {
				if rem := e[slot].Sub(now).Round(time.Second); rem > time.Second {
					batches[rem] = append(batches[rem], a)
				}
			}
			for rem, as := range batches {
				if err := p.w.Add(base+string(rune('a'+slot)), as, rem); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
