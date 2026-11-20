package winsplit

import "sync/atomic"

// RebindGate decides when the tunnels must open their sockets again after
// the uplink was cut under them without its interface index changing:
// restarting the cable adapter (MAC disguise), a cable pulled and plugged
// again, the adapter reset by a driver. The WireGuard sockets of the old
// state do not recover by themselves; without a rebind every tunnel stays
// silent until the "no answers" watchdog fires (about 90 s, measured 114 s).
//
// Two triggers: Request (the disguise restarted an adapter) and an offline
// gap seen by the poll. In both cases Poll answers true once, when the
// uplink is back.
type RebindGate struct {
	pending    atomic.Bool
	wasOffline bool // only touched by the poll loop
}

// Request asks for a rebind as soon as the uplink is up.
func (g *RebindGate) Request() { g.pending.Store(true) }

// Poll is called on every uplink poll with whether an uplink was found. It
// returns true when the tunnels must be rebound now.
func (g *RebindGate) Poll(online bool) bool {
	if !online {
		g.wasOffline = true
		return false // keep a pending request until the uplink is back
	}
	was := g.wasOffline
	g.wasOffline = false
	return g.pending.Swap(false) || was
}
