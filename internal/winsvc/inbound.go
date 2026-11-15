package winsvc

import (
	"sort"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
)

// MaxDecoyPermits bounds the decoy ports let in (the inbound filter set
// has room for 512 filters, two per port).
const MaxDecoyPermits = 64

// InboundAction says what the inbound protection does on network (a
// [[network]] name, "" = unknown): off (no filters), closed or lan with the
// open ports. The config decides; "open" and a disabled [inbound] are off.
//
// Decoys are the ports the defense's decoys listen on right now (they only
// run outside safe networks, see defense.Class.Decoys); they are let in to
// the service in every mode. With the protection off and decoys running,
// On and Open are both set: only the decoy permits, no block.
type InboundAction struct {
	On     bool
	LAN    bool
	Open   bool
	Ports  []config.PortSel
	Decoys []uint16
}

func InboundFor(c *config.Config, network string, decoys []int) InboundAction {
	var a InboundAction
	mode, ports := c.InboundFor(network)
	switch mode {
	case config.InboundClosed:
		a = InboundAction{On: true}
	case config.InboundLAN:
		a = InboundAction{On: true, LAN: true, Ports: ports}
	}
	seen := map[int]bool{}
	for _, p := range decoys {
		if p <= 0 || p > 65535 || seen[p] || len(a.Decoys) >= MaxDecoyPermits {
			continue
		}
		seen[p] = true
		a.Decoys = append(a.Decoys, uint16(p))
	}
	sort.Slice(a.Decoys, func(i, j int) bool { return a.Decoys[i] < a.Decoys[j] })
	if !a.On && len(a.Decoys) > 0 {
		a.On, a.Open = true, true
	}
	return a
}
