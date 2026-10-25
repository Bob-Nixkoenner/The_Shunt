package config

import "fmt"

// Inbound modes: what may reach this machine from the network it is on.
const (
	InboundClosed = "closed" // nothing new comes in (answers to your own connections do)
	InboundLAN    = "lan"    // the ports in allow, from private addresses only
	InboundOpen   = "open"   // no filtering (as without The Shunt)
)

// Inbound configures the protection against incoming connections. Off
// unless enabled: switched on, everything without a profile that says
// otherwise is closed, also SSH on a server.
type Inbound struct {
	Enabled bool `toml:"enabled" json:"enabled"`
	// Allow: what a "lan" network lets in when it lists nothing itself,
	// e.g. ["tcp/1716", "udp/1716"] for KDE Connect.
	Allow []string `toml:"allow,omitempty" json:"allow,omitempty"`
}

// InboundFor returns the inbound mode and open ports on network (a
// [[network]] name, "" = unknown network). mode is "" while the
// protection is off.
func (c *Config) InboundFor(network string) (mode string, allow []PortSel) {
	if c.Inbound == nil || !c.Inbound.Enabled {
		return "", nil
	}
	mode, list := InboundClosed, c.Inbound.Allow
	for _, n := range c.Networks {
		if n.Name == network && network != "" {
			if n.Inbound != "" {
				mode = n.Inbound
			}
			if n.InboundAllow != nil {
				list = n.InboundAllow
			}
		}
	}
	if mode != InboundLAN {
		return mode, nil
	}
	for _, s := range list {
		if p, err := ParsePort(s); err == nil {
			allow = append(allow, p)
		}
	}
	return mode, allow
}

func validInbound(m string) bool {
	return m == "" || m == InboundClosed || m == InboundLAN || m == InboundOpen
}

func (c *Config) validateInbound() error {
	if c.Inbound != nil {
		for _, s := range c.Inbound.Allow {
			if _, err := ParsePort(s); err != nil {
				return fmt.Errorf("inbound.allow: %w", err)
			}
		}
	}
	for _, n := range c.Networks {
		if !validInbound(n.Inbound) {
			return fmt.Errorf("network %q: inbound %q (closed | lan | open)", n.Name, n.Inbound)
		}
		for _, s := range n.InboundAllow {
			if _, err := ParsePort(s); err != nil {
				return fmt.Errorf("network %q: inbound_allow: %w", n.Name, err)
			}
		}
	}
	return nil
}
