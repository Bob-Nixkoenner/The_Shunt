package winsplit

import "github.com/Bob-Nixkoenner/the_shunt/internal/winsplit/wfp"

// InboundPort is a port that "lan" mode lets in (TCP or UDP, From..To).
type InboundPort = wfp.InboundPort

// EnableInbound blocks new inbound connections (see wfp.EnableInbound);
// lan lets the ports in from private addresses, tunLUID never opens.
func EnableInbound(lan bool, allow []InboundPort, tunLUID uint64) error {
	return wfp.EnableInbound(wfp.InboundPolicy{LAN: lan, Allow: allow, TunLUID: tunLUID})
}

// DisableInbound removes the inbound filters.
func DisableInbound() { _ = wfp.DisableInbound() }
