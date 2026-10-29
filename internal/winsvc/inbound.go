package winsvc

import "github.com/Bob-Nixkoenner/the_shunt/internal/config"

// InboundAction says what the inbound protection does on network (a
// [[network]] name, "" = unknown): off (no filters), closed or lan with the
// open ports. The config decides; "open" and a disabled [inbound] are off.
type InboundAction struct {
	On    bool
	LAN   bool
	Ports []config.PortSel
}

func InboundFor(c *config.Config, network string) InboundAction {
	mode, ports := c.InboundFor(network)
	switch mode {
	case config.InboundClosed:
		return InboundAction{On: true}
	case config.InboundLAN:
		return InboundAction{On: true, LAN: true, Ports: ports}
	}
	return InboundAction{}
}
