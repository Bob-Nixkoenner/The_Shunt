package routing

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/Bob-Nixkoenner/the_shunt/internal/engine"
)

// UnreachableMetric keeps the kill switch route behind real tunnel routes.
const UnreachableMetric = 4096

// families lists the address families the kernel supports. A kernel without
// IPv6 cannot leak IPv6, so there is nothing to route or block there.
var families = func() []int {
	if _, err := os.Stat("/proc/sys/net/ipv6"); err != nil {
		return []int{netlink.FAMILY_V4}
	}
	return []int{netlink.FAMILY_V4, netlink.FAMILY_V6}
}()

func haveFamily(fam int) bool {
	for _, f := range families {
		if f == fam {
			return true
		}
	}
	return false
}

// Sync makes the kernel routing state match the plan. It never empties a
// table on the way: kill switch routes are put in place before anything is
// removed. ifaceUp tells which tunnel interfaces currently exist.
func Sync(p *engine.Plan, ifaceUp map[string]bool) error {
	if err := os.WriteFile("/proc/sys/net/ipv4/conf/all/src_valid_mark", []byte("1"), 0); err != nil {
		return fmt.Errorf("src_valid_mark: %w", err)
	}
	var errs []error
	wantRules := map[int]uint32{}
	var lan []netlink.Route
	for _, r := range p.Routes {
		if r.AllowLAN {
			lan = lanRoutes(p)
			break
		}
	}
	for _, r := range p.Routes {
		if r.Kind == config.RouteLink {
			wantRules[r.Table] = r.Mark
			errs = append(errs, syncLinkTable(r))
			continue
		}
		if r.Kind != config.RouteTunnel {
			continue
		}
		wantRules[r.Table] = r.Mark
		var extra []netlink.Route
		if r.AllowLAN {
			extra = lan
		}
		errs = append(errs, syncTable(r, ifaceUp[r.Iface], extra))
	}
	errs = append(errs, syncRules(wantRules))
	errs = append(errs, enableForwarding(p.Uplinks()))
	return errors.Join(errs...)
}

// lanRoutes returns the directly attached private networks of the main
// table (what allow_lan routes may reach past their tunnel).
func lanRoutes(p *engine.Plan) []netlink.Route {
	tunnels := map[string]bool{}
	for _, r := range p.Routes {
		if r.Kind == config.RouteTunnel { // link routes name physical interfaces
			tunnels[r.Iface] = true
		}
	}
	var lan []netip.Prefix
	for _, s := range append(append([]string{}, engine.LANv4...), engine.LANv6...) {
		lan = append(lan, netip.MustParsePrefix(s))
	}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return nil
	}
	var out []netlink.Route
	for _, rt := range routes {
		if rt.Dst == nil || rt.Scope != netlink.SCOPE_LINK || rt.Gw != nil {
			continue
		}
		if l, err := netlink.LinkByIndex(rt.LinkIndex); err != nil || tunnels[l.Attrs().Name] {
			continue
		}
		pfx, ok := netip.AddrFromSlice(rt.Dst.IP)
		if !ok {
			continue
		}
		ones, _ := rt.Dst.Mask.Size()
		dst := netip.PrefixFrom(pfx.Unmap(), ones)
		if dst.Addr().IsLinkLocalUnicast() {
			continue // one per interface, needs a zone anyway
		}
		for _, l := range lan {
			if l.Contains(dst.Addr()) && dst.Bits() >= l.Bits() {
				out = append(out, rt)
				break
			}
		}
	}
	return out
}

// syncLinkTable fills a link route's table with the main table's routes
// through its interface (default route via the gateway, the attached
// subnets). Without the interface only the unreachable routes stay.
func syncLinkTable(r *engine.Route) error {
	var want []*netlink.Route
	if r.Iface != "" {
		if link, err := netlink.LinkByName(r.Iface); err == nil {
			main, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_TABLE)
			if err != nil {
				return err
			}
			for _, rt := range main {
				if rt.LinkIndex != link.Attrs().Index || rt.Type != unix.RTN_UNICAST || rt.MultiPath != nil {
					continue
				}
				if rt.Dst != nil && rt.Dst.IP.IsLinkLocalUnicast() {
					continue // fe80::/64 exists on every interface
				}
				want = append(want, &netlink.Route{
					Family:    rt.Family,
					LinkIndex: rt.LinkIndex,
					Type:      unix.RTN_UNICAST,
					Table:     r.Table,
					Dst:       rt.Dst,
					Gw:        rt.Gw,
					Src:       rt.Src,
					Scope:     rt.Scope,
					Priority:  min(rt.Priority, UnreachableMetric-1),
				})
			}
		}
	}
	return applyTable(r.Table, nil, want)
}

func syncTable(r *engine.Route, up bool, lan []netlink.Route) error {
	var want, soft []*netlink.Route
	for _, l := range lan {
		soft = append(soft, &netlink.Route{
			LinkIndex: l.LinkIndex,
			Type:      unix.RTN_UNICAST,
			Table:     r.Table,
			Dst:       l.Dst,
			Scope:     netlink.SCOPE_LINK,
			Src:       l.Src,
		})
	}
	var link netlink.Link
	if up {
		var err error
		if link, err = netlink.LinkByName(r.Iface); err != nil {
			link = nil // gone meanwhile (an openvpn restart): stay unreachable
		}
	}
	if link != nil {
		// OpenVPN gets its addresses from the server, after connecting.
		has4, has6 := hasAddr(link, netlink.FAMILY_V4), hasAddr(link, netlink.FAMILY_V6)
		for _, pfx := range r.AllowedIPs {
			if (pfx.Addr().Is4() && (!r.V4 || !has4)) || (pfx.Addr().Is6() && (!r.V6 || !has6 || !haveFamily(netlink.FAMILY_V6))) {
				continue // no source address of that family: keep it unreachable
			}
			rt := &netlink.Route{
				LinkIndex: link.Attrs().Index,
				Type:      unix.RTN_UNICAST,
				Table:     r.Table,
				Dst:       ipnet(pfx),
				Scope:     netlink.SCOPE_LINK,
			}
			if r.Gateway.IsValid() && r.Gateway.Is4() == pfx.Addr().Is4() {
				rt.Gw, rt.Scope, rt.Flags = r.Gateway.AsSlice(), netlink.SCOPE_UNIVERSE, int(netlink.FLAG_ONLINK)
			}
			want = append(want, rt)
		}
	}
	return applyTable(r.Table, want, soft)
}

// applyTable makes table hold the unreachable defaults plus want: new
// routes first, stale ones removed after (never an empty table).
// Failing soft routes (copies of link/LAN routes) give SoftErrors.
func applyTable(table int, routes, soft []*netlink.Route) error {
	// unreachable first: a fresh table must never hold only some routes,
	// misses would fall through to the main table
	var want []*netlink.Route
	for _, fam := range families {
		want = append(want, &netlink.Route{
			Family:   fam,
			Table:    table,
			Type:     unix.RTN_UNREACHABLE,
			Dst:      defaultDst(fam),
			Priority: UnreachableMetric,
		})
	}
	want = append(want, routes...)
	var errs []error
	for _, rt := range want {
		if err := netlink.RouteReplace(rt); err != nil {
			// one odd route (a gateway gone meanwhile) must not keep the
			// others out
			errs = append(errs, fmt.Errorf("table %d route %v: %w", table, rt.Dst, err))
		}
	}
	// copies of the interfaces' own routes: may fail while a link comes up
	for _, rt := range soft {
		if err := netlink.RouteReplace(rt); err != nil {
			errs = append(errs, &SoftError{fmt.Errorf("table %d route %v via %v: %w", table, rt.Dst, rt.Gw, err)})
		}
	}
	want = append(want, soft...)
	// remove stale routes
	have, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return err
	}
	for _, h := range have {
		keep := false
		for _, w := range want {
			if sameRoute(h, w) {
				keep = true
				break
			}
		}
		if !keep {
			_ = netlink.RouteDel(&h)
		}
	}
	return errors.Join(errs...)
}

// hasAddr reports whether link has a usable (not link-local) address of fam.
func hasAddr(link netlink.Link, fam int) bool {
	addrs, err := netlink.AddrList(link, fam)
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if !a.IP.IsLinkLocalUnicast() {
			return true
		}
	}
	return false
}

func sameRoute(a netlink.Route, b *netlink.Route) bool {
	return a.Type == b.Type && a.Priority == b.Priority && a.LinkIndex == b.LinkIndex &&
		dstString(a.Dst, a.Family) == dstString(b.Dst, b.Family) && a.Gw.Equal(b.Gw)
}

func dstString(d *net.IPNet, fam int) string {
	if d == nil {
		return defaultDst(fam).String()
	}
	return d.String()
}

func defaultDst(fam int) *net.IPNet {
	if fam == netlink.FAMILY_V6 {
		return &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}
	}
	return &net.IPNet{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)}
}

func syncRules(want map[int]uint32) error {
	var errs []error
	for _, fam := range families {
		have, err := netlink.RuleList(fam)
		if err != nil {
			return err
		}
		present := map[int]bool{}
		for _, h := range have {
			if h.Priority != engine.RulePriority {
				continue
			}
			if m, ok := want[h.Table]; ok && h.Mark == m {
				present[h.Table] = true
				continue
			}
			h := h
			errs = append(errs, netlink.RuleDel(&h))
		}
		for table, mark := range want {
			if present[table] {
				continue
			}
			r := netlink.NewRule()
			r.Family = fam
			r.Priority = engine.RulePriority
			r.Mark = mark
			mask := uint32(0xffffffff)
			r.Mask = &mask
			r.Table = table
			errs = append(errs, netlink.RuleAdd(r))
		}
	}
	return errors.Join(errs...)
}

// Cleanup removes all Shunt rules and tables. This lifts the kill switch;
// only used by an explicit `shuntd cleanup`.
func Cleanup() error {
	if err := syncRules(nil); err != nil {
		return err
	}
	for _, fam := range families {
		rs, err := netlink.RouteListFiltered(fam, &netlink.Route{Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_TABLE)
		if err != nil {
			return err
		}
		for _, r := range rs {
			if r.Table >= engine.TableBase && r.Table < engine.TableBase+0xf0 {
				r := r
				_ = netlink.RouteDel(&r)
			}
		}
	}
	return nil
}

func ipnet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}

// enableForwarding turns forwarding on for the uplinks: replies to what a
// Tailscale tunnel's namespace sent arrive there and are forwarded back
// into it. Per interface, not globally; the ruleset's fwd_guard keeps
// everything else from using it.
func enableForwarding(uplinks []string) error {
	var errs []error
	for _, u := range uplinks {
		if _, err := netlink.LinkByName(u); err != nil {
			continue // not up (yet): the next sync does it
		}
		if err := os.WriteFile("/proc/sys/net/ipv4/conf/"+u+"/forwarding", []byte("1"), 0); err != nil {
			errs = append(errs, fmt.Errorf("forwarding on %s: %w", u, err))
		}
	}
	return errors.Join(errs...)
}
