package winsplit

import "github.com/Bob-Nixkoenner/the_shunt/internal/winsplit/wfp"

// InboundPort is a port that "lan" mode lets in (TCP or UDP, From..To).
type InboundPort = wfp.InboundPort

// InboundPolicy is what the inbound filters let in (see wfp.InboundPolicy).
type InboundPolicy = wfp.InboundPolicy

// EnableInbound blocks new inbound connections (see wfp.EnableInbound):
// LAN lets the ports in from private addresses, the decoy ports come in to
// the service only, the tunnel never opens.
func EnableInbound(p InboundPolicy) error { return wfp.EnableInbound(p) }

// DisableInbound removes the inbound filters.
func DisableInbound() { _ = wfp.DisableInbound() }

// Banner installs the defense's bans (dynamic WFP session, see wfp.Banner).
type Banner = wfp.Banner

// OpenBanner removes bans an earlier run left and opens the ban filters.
func OpenBanner() (*Banner, error) { return wfp.OpenBanner() }
