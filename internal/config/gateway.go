package config

import (
	"fmt"
	"regexp"
	"slices"
)

// Gateway lets this machine route the traffic of other devices, VMs and
// containers (behind the interfaces of its groups) through The Shunt: each
// group has one route and is held to it (Linux only; ignored elsewhere).
type Gateway struct {
	Enabled bool `toml:"enabled" json:"enabled"`
	// IPv6: "block" (default) drops what clients send over IPv6; "pass" is
	// not implemented yet.
	IPv6  string         `toml:"ipv6,omitempty" json:"ipv6,omitempty"`
	Group []GatewayGroup `toml:"group,omitempty" json:"group,omitempty"`
}

// GatewayGroup is a set of client-side interfaces with one route.
type GatewayGroup struct {
	Name       string   `toml:"name" json:"name"`
	Interfaces []string `toml:"interfaces" json:"interfaces"`
	// Route: direct | block | tunnel:<name> | link:<kind>. Empty = block.
	Route string `toml:"route,omitempty" json:"route,omitempty"`
}

const (
	GatewayIPv6Block = "block"
	GatewayIPv6Pass  = "pass"
)

var ifaceRe = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`)

// GatewayOn reports whether the gateway mode is switched on and has groups.
func (c *Config) GatewayOn() bool {
	return c.Gateway != nil && c.Gateway.Enabled && len(c.Gateway.Group) > 0
}

// RouteOrBlock is the route of group g ("" = block).
func (g GatewayGroup) RouteOrBlock() string {
	if g.Route == "" {
		return "block"
	}
	return g.Route
}

func (c *Config) validateGateway() error {
	g := c.Gateway
	if g == nil {
		return nil
	}
	switch g.IPv6 {
	case "", GatewayIPv6Block:
	case GatewayIPv6Pass:
		return fmt.Errorf("gateway: ipv6 = \"pass\" is not implemented yet (use \"block\")")
	default:
		return fmt.Errorf("gateway: ipv6 %q (block)", g.IPv6)
	}
	var seen []string
	names := map[string]bool{}
	for i, gr := range g.Group {
		where := fmt.Sprintf("gateway group %d", i+1)
		if !ValidName(gr.Name) {
			return fmt.Errorf("%s: name must match %s", where, nameRe)
		}
		where = fmt.Sprintf("gateway group %q", gr.Name)
		if names[gr.Name] {
			return fmt.Errorf("%s: name used twice", where)
		}
		names[gr.Name] = true
		if len(gr.Interfaces) == 0 {
			return fmt.Errorf("%s: interfaces missing", where)
		}
		for _, ifn := range gr.Interfaces {
			if !ifaceRe.MatchString(ifn) || ifn == "lo" {
				return fmt.Errorf("%s: invalid interface %q", where, ifn)
			}
			if slices.Contains(seen, ifn) {
				return fmt.Errorf("%s: interface %q is in another group (or twice)", where, ifn)
			}
			seen = append(seen, ifn)
			for n, t := range c.Tunnels {
				if t.Interface == ifn || (t.Interface == "" && !t.IsTor() && ifn == "sh-"+n) {
					return fmt.Errorf("%s: interface %q is the interface of tunnel %q", where, ifn, n)
				}
			}
		}
		r, err := c.ParseRoute(gr.RouteOrBlock())
		if err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}
		if r.Kind == RouteTunnel && c.Tunnels[r.Tunnel].IsTor() {
			return fmt.Errorf("%s: a Tor tunnel as route is not available for clients yet (stage 2)", where)
		}
	}
	return nil
}
