// Package engine compiles a validated config into a platform neutral plan:
// routes with marks and routing tables, process groups, and ordered rules.
// Backends translate the plan into native mechanisms.
package engine

import (
	"fmt"
	"net/netip"
	"path"
	"sort"
	"strings"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
)

// Packet marks. The upper bytes identify Shunt, the low byte the route.
const (
	MarkBase   uint32 = 0x530000
	MarkMask   uint32 = 0xffff00
	MarkDirect uint32 = MarkBase | 0xf0
	MarkBlock  uint32 = MarkBase | 0xfe
	// MarkBypass is set by the tunnel itself on its encrypted UDP packets so
	// they never get routed into a tunnel (no routing loops).
	MarkBypass uint32 = MarkBase | 0xff
	// TableBase is the first routing table used for tunnels.
	TableBase = 5300
	// RulePriority is the ip rule priority used for all Shunt rules
	// (well before the main table at 32766).
	RulePriority = 5300
)

// TunnelInfo carries what the plan needs to know about a tunnel's config.
type TunnelInfo struct {
	Iface      string
	HasV4      bool
	HasV6      bool
	AllowedIPs []netip.Prefix
}

// Route is a compiled route.
type Route struct {
	config.Route
	Mark  uint32
	Table int // 0 for direct/block
	Iface string
	V4    bool // tunnel carries IPv4
	V6    bool // tunnel carries IPv6
	// Prefixes routed into the tunnel (union of the peers' AllowedIPs).
	AllowedIPs []netip.Prefix
}

// Group is a process group backed by a cgroup.
type Group struct {
	Name string // "browser" or "via:tunnel:vps"
	Path string // relative to the cgroup2 mount, no leading slash
}

// Level is the cgroup depth nftables needs for `socket cgroupv2 level`.
func (g Group) Level() int { return strings.Count(g.Path, "/") + 1 }

// Rule is a compiled rule. Empty selector lists mean "any".
type Rule struct {
	Name   string
	Groups []Group
	V4, V6 []netip.Prefix
	Ports  []config.PortSel
	// AnyFamily is true when the rule has no CIDR selector.
	AnyFamily bool
	Route     *Route
}

// Plan is everything a backend needs to enforce the config.
type Plan struct {
	CgroupRoot   string
	DaemonGroup  Group
	Routes       []*Route
	Groups       []Group // user groups and implicit via-groups
	Rules        []Rule
	DefaultRoute *Route
}

// RouteByName finds a route by its string form ("tunnel:vps").
func (p *Plan) RouteByName(s string) *Route {
	for _, r := range p.Routes {
		if r.String() == s {
			return r
		}
	}
	return nil
}

// Group finds a group by name.
func (p *Plan) Group(name string) (Group, bool) {
	for _, g := range p.Groups {
		if g.Name == name {
			return g, true
		}
	}
	return Group{}, false
}

// ViaGroupName is the implicit group for `shunt run --via <route>`.
func ViaGroupName(route string) string { return "via:" + route }

// Compile builds a plan. tunnels must contain info for every configured tunnel.
func Compile(c *config.Config, cgroupRoot string, tunnels map[string]TunnelInfo) (*Plan, error) {
	cgroupRoot = strings.Trim(cgroupRoot, "/")
	p := &Plan{
		CgroupRoot:  cgroupRoot,
		DaemonGroup: Group{Name: "daemon", Path: path.Join(cgroupRoot, "daemon")},
	}
	tIdx := 0
	for _, cr := range c.Routes() {
		r := &Route{Route: cr}
		switch cr.Kind {
		case config.RouteDirect:
			r.Mark = MarkDirect
		case config.RouteBlock:
			r.Mark = MarkBlock
		case config.RouteTunnel:
			tIdx++
			if tIdx >= 0xf0 {
				return nil, fmt.Errorf("too many tunnels")
			}
			ti, ok := tunnels[cr.Tunnel]
			if !ok {
				return nil, fmt.Errorf("no tunnel info for %q", cr.Tunnel)
			}
			r.Mark = MarkBase | uint32(tIdx)
			r.Table = TableBase + tIdx
			r.Iface = ti.Iface
			r.V4, r.V6 = ti.HasV4, ti.HasV6
			r.AllowedIPs = ti.AllowedIPs
		}
		p.Routes = append(p.Routes, r)
	}

	names := make([]string, 0, len(c.Groups))
	for n := range c.Groups {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		p.Groups = append(p.Groups, Group{Name: n, Path: path.Join(cgroupRoot, "apps", "g", n)})
	}
	for _, r := range p.Routes {
		slug := strings.ReplaceAll(r.String(), ":", "-")
		p.Groups = append(p.Groups, Group{Name: ViaGroupName(r.String()), Path: path.Join(cgroupRoot, "apps", "via", slug)})
	}

	for _, cr := range c.Rules {
		route, _ := c.ParseRoute(cr.Route) // validated
		rule := Rule{Name: cr.Name, Route: p.RouteByName(route.String()), AnyFamily: len(cr.CIDR) == 0}
		for _, g := range cr.Group {
			grp, _ := p.Group(g)
			rule.Groups = append(rule.Groups, grp)
		}
		for _, s := range cr.CIDR {
			pfx, _ := config.ParseCIDR(s)
			if pfx.Addr().Is4() {
				rule.V4 = append(rule.V4, pfx)
			} else {
				rule.V6 = append(rule.V6, pfx)
			}
		}
		for _, s := range cr.Port {
			ps, _ := config.ParsePort(s)
			rule.Ports = append(rule.Ports, ps)
		}
		p.Rules = append(p.Rules, rule)
	}
	// Implicit rules: processes started with `shunt run --via X` take route X.
	// They come after explicit rules so specific rules (e.g. "SSH direct")
	// still win, as described in the design.
	for _, r := range p.Routes {
		g, _ := p.Group(ViaGroupName(r.String()))
		p.Rules = append(p.Rules, Rule{Name: g.Name, Groups: []Group{g}, AnyFamily: true, Route: r})
	}

	dr, _ := c.ParseRoute(c.Daemon.DefaultRoute)
	p.DefaultRoute = p.RouteByName(dr.String())
	return p, nil
}
