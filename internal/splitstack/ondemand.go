package splitstack

import (
	"strings"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/health"
)

// On-demand tunnels: a WireGuard tunnel that no app uses is closed after
// idleAfter (no keepalives, no wakeups: battery) and made again when the
// first connection of an app on its route arrives. Until then its slot in
// the tunnel map is a dormant stand-in that only keeps the config.
//
// Only WireGuard tunnels take part, and not the ones an OpenVPN tunnel
// runs through (tunnelConf.Via): those are needed all the time.

// idleAfter is how long a tunnel may be unused before it is closed.
var idleAfter = 3 * time.Minute

func (e *Engine) tunnel(name string) *wgTunnel {
	e.tunMu.RLock()
	defer e.tunMu.RUnlock()
	return e.tunnels[name]
}

func (e *Engine) setTunnel(name string, t *wgTunnel) {
	e.tunMu.Lock()
	e.tunnels[name] = t
	e.tunMu.Unlock()
}

// allTunnels is a snapshot of the tunnel map (slots may be swapped meanwhile).
func (e *Engine) allTunnels() []*wgTunnel {
	e.tunMu.RLock()
	defer e.tunMu.RUnlock()
	ts := make([]*wgTunnel, 0, len(e.tunnels))
	for _, t := range e.tunnels {
		ts = append(ts, t)
	}
	return ts
}

// onDemandEligible: whether a tunnel may sleep at all.
func onDemandEligible(t tunnelConf, all []tunnelConf) bool {
	if t.Type != typeWireGuard || t.Via != "" { // a tunnel inside another one keeps its socket there
		return false
	}
	for _, o := range all {
		if o.Via == t.Name {
			return false
		}
	}
	return true
}

// dormantTunnel is the stand-in of a sleeping tunnel.
func dormantTunnel(name, conf string) *wgTunnel {
	return &wgTunnel{name: name, lazy: true, dormant: true, lazyConf: conf}
}

// use notes that something wanted the tunnel just now (dial).
func (t *wgTunnel) use() { t.lastUse.Store(time.Now().UnixNano()) }

// wake makes a sleeping tunnel (a no-op for a running one) and returns the
// running tunnel, or nil if it cannot be made now (e.g. the endpoint name
// does not resolve while offline: the next connection tries again).
func (e *Engine) wake(name string) *wgTunnel {
	e.wakeMu.Lock()
	defer e.wakeMu.Unlock()
	t := e.tunnel(name)
	if t == nil || !t.dormant {
		return t
	}
	wt, err := newWGTunnel(name, t.lazyConf, e.resolver(), e.o.NewBind(), e.o.BindUp, e.mtu)
	if err != nil {
		e.logf("tunnel %s: waking up failed: %v", name, err)
		return nil
	}
	wt.lazy, wt.lazyConf = true, t.lazyConf
	wt.use()
	e.setTunnel(name, wt)
	// a new userspace tunnel starts at zero: count from the first byte
	e.book.Observe(name, 0, 0, time.Now())
	e.logf("tunnel %s: awake (on demand)", name)
	return wt
}

// wakeAll makes every sleeping tunnel (on demand was turned off).
func (e *Engine) wakeAll() {
	for _, t := range e.allTunnels() {
		if t.dormant {
			e.wake(t.name)
		}
	}
}

// routeBusy: a running connection uses the route.
func (e *Engine) routeBusy(route string) bool {
	e.actMu.Lock()
	defer e.actMu.Unlock()
	for f := range e.active {
		if f.route == route && !f.dnsTried.IsValid() { // a DNS flow lingers after its query: relayDNS notes each query itself
			return true
		}
	}
	return false
}

// touch notes that a route (a tunnel) is wanted now.
func (e *Engine) touch(route string) {
	if name, ok := strings.CutPrefix(route, tunnelPref); ok {
		if t := e.tunnel(name); t != nil {
			t.use()
		}
	}
}

// sleepIdle closes the tunnels nobody used for idleAfter (health loop), or
// wakes all of them when on demand is off.
func (e *Engine) sleepIdle(now time.Time) {
	if !e.onDemand.Load() {
		e.wakeAll()
		return
	}
	for _, t := range e.allTunnels() {
		if !t.lazy || t.dormant || t.dev == nil {
			continue
		}
		if now.Sub(time.Unix(0, t.lastUse.Load())) < idleAfter || e.routeBusy(tunnelPref+t.name) {
			continue
		}
		st := t.status() // the last bytes, before the counters are gone
		e.book.Observe(t.name, st.RX, st.TX, now)
		e.setTunnel(t.name, dormantTunnel(t.name, t.lazyConf))
		t.close()
		e.logf("tunnel %s: asleep (unused for %s)", t.name, idleAfter)
	}
}

// dormantStatus is what the UI sees of a sleeping tunnel.
func (t *wgTunnel) dormantStatus() tunnelStatus {
	return tunnelStatus{Name: t.name, Type: typeWireGuard, Idle: true, Health: health.Report{State: health.Idle, HandshakeAge: -1}}
}
