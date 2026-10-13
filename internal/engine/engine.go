// Package engine compiles a validated config into a platform neutral plan:
// routes with marks and routing tables, process groups, and ordered rules.
// Backends translate the plan into native mechanisms.
package engine

import (
	"fmt"
	"net/netip"
	"path"
	"slices"
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
	// LinkSlot is the first mark/table slot of the link routes (after
	// the tunnels, before MarkDirect).
	LinkSlot = 0xe0
	// DNSPortBase: the DNS proxy listens on 127.0.0.1/[::1] at
	// DNSPortBase + route index; queries are redirected there per route.
	DNSPortBase = 53530
	// RulePriority is the ip rule priority used for all Shunt rules
	// (well before the main table at 32766).
	RulePriority = 5300
)

// Private ranges a route with allow_lan may reach past its tunnel (only the
// parts that are directly attached to the machine are routed there).
var (
	LANv4 = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"}
	LANv6 = []string{"fc00::/7", "fe80::/10"}
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
	// DNSPort is where the DNS proxy listens for this route's queries.
	DNSPort int
	// AllowLAN: directly attached private networks go past the tunnel.
	AllowLAN bool
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
	// AnyFamily is true when the rule has no destination selector.
	AnyFamily bool
	// Domains (normalized). The DNS proxy fills the rule's address sets
	// with what these names resolve to.
	Domains []string
	SetV4   string
	SetV6   string
	// Apps: processes matching these are moved into Groups[0] when they
	// start (the daemon's app watcher does that).
	Apps  []config.AppSel
	Args  []string // command line must contain one of these (if any)
	Route *Route
}

// Plan is everything a backend needs to enforce the config.
type Plan struct {
	CgroupRoot   string
	DaemonGroup  Group
	Routes       []*Route
	Groups       []Group // user groups and implicit via-groups
	Rules        []Rule
	DefaultRoute *Route
	DNS          bool // per-route DNS proxy + redirection active
	BlockDoT     bool
	BlockDoH     bool
}

// AppRules returns the rules with app selectors, in order.
func (p *Plan) AppRules() []*Rule {
	var out []*Rule
	for i := range p.Rules {
		if len(p.Rules[i].Apps) > 0 {
			out = append(out, &p.Rules[i])
		}
	}
	return out
}

// DomainRules returns the rules with domain selectors, in order.
func (p *Plan) DomainRules() []*Rule {
	var out []*Rule
	for i := range p.Rules {
		if len(p.Rules[i].Domains) > 0 {
			out = append(out, &p.Rules[i])
		}
	}
	return out
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
	return CompileOn(c, cgroupRoot, tunnels, "", nil)
}

// CompileOn builds the plan for the network profile network ("" = none
// matched): rules limited to other networks are left out.
//
// Rule order (first match wins):
//  1. programs started in the block route – nothing overrides block
//  2. rules with override_explicit = true
//  3. programs started in a route on purpose (shunt run --via, menu entries)
//  4. all other rules
//  5. the default route
//
// links maps a link kind ("wifi") to its connected interface; a link route
// without one gets no interface and blocks.
func CompileOn(c *config.Config, cgroupRoot string, tunnels map[string]TunnelInfo, network string, links map[string]string) (*Plan, error) {
	cgroupRoot = strings.Trim(cgroupRoot, "/")
	p := &Plan{
		CgroupRoot:  cgroupRoot,
		DaemonGroup: Group{Name: "daemon", Path: path.Join(cgroupRoot, "daemon")},
	}
	p.DNS = !c.DNS.Disabled
	p.BlockDoT = p.DNS && !c.DNS.AllowDoT
	p.BlockDoH = p.DNS && !c.DNS.AllowDoH
	tIdx := 0
	for i, cr := range c.Routes() {
		r := &Route{Route: cr, DNSPort: DNSPortBase + i}
		switch cr.Kind {
		case config.RouteDirect:
			r.Mark = MarkDirect
		case config.RouteBlock:
			r.Mark = MarkBlock
		case config.RouteTunnel:
			tIdx++
			if tIdx >= LinkSlot {
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
			r.AllowLAN = c.Tunnels[cr.Tunnel].AllowLAN
		case config.RouteLink:
			slot := LinkSlot + slices.Index(config.LinkKinds, cr.Link)
			r.Mark = MarkBase | uint32(slot)
			r.Table = TableBase + slot
			r.Iface = links[cr.Link]
			r.V4, r.V6 = true, true
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

	var override, normal []Rule
	for i, cr := range c.Rules {
		if !cr.ActiveOn(network) {
			continue // names below keep using i: stable across networks
		}
		route, _ := c.ParseRoute(cr.Route) // validated
		rule := Rule{Name: cr.Name, Route: p.RouteByName(route.String()), AnyFamily: len(cr.CIDR)+len(cr.Domain) == 0}
		if rule.Name == "" {
			rule.Name = fmt.Sprintf("rule %d", i+1)
		}
		for _, d := range cr.Domain {
			rule.Domains = append(rule.Domains, config.NormalizeDomain(d))
		}
		if len(rule.Domains) > 0 {
			rule.SetV4 = fmt.Sprintf("dom%d_v4", i+1)
			rule.SetV6 = fmt.Sprintf("dom%d_v6", i+1)
		}
		for _, g := range cr.Group {
			grp, _ := p.Group(g)
			rule.Groups = append(rule.Groups, grp)
		}
		if len(cr.App) > 0 {
			grp := Group{Name: "app:" + rule.Name, Path: path.Join(cgroupRoot, "apps", "app", fmt.Sprintf("r%d", i+1))}
			p.Groups = append(p.Groups, grp)
			rule.Groups = []Group{grp}
			rule.Args = cr.Args
			for _, a := range cr.App {
				sel, _ := config.ParseAppSel(a)
				rule.Apps = append(rule.Apps, sel)
			}
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
		if cr.OverrideExplicit {
			override = append(override, rule)
		} else {
			normal = append(normal, rule)
		}
	}
	// Implicit rules: processes started with `shunt run --via X` take
	// route X. Block first, before anything; the others after the rules
	// that explicitly override them.
	via := func(r *Route) Rule {
		g, _ := p.Group(ViaGroupName(r.String()))
		return Rule{Name: g.Name, Groups: []Group{g}, AnyFamily: true, Route: r}
	}
	p.Rules = append(p.Rules, via(p.RouteByName("block")))
	p.Rules = append(p.Rules, override...)
	for _, r := range p.Routes {
		if r.Kind != config.RouteBlock {
			p.Rules = append(p.Rules, via(r))
		}
	}
	p.Rules = append(p.Rules, normal...)

	dr, _ := c.ParseRoute(c.Daemon.DefaultRoute)
	p.DefaultRoute = p.RouteByName(dr.String())
	return p, nil
}
