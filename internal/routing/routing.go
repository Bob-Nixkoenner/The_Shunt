// Package routing maintains Shunt's policy routing: one table per tunnel and
// an ip rule per tunnel mark.
//
// Every tunnel table permanently holds an "unreachable default" route with a
// high metric. When the tunnel interface is gone its routes vanish with it,
// the unreachable route stays, and marked traffic gets ENETUNREACH instead of
// falling through to the main table. The kill switch is a property of the
// table, not of a running daemon.
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
	for _, r := range p.Routes {
		if r.Kind != config.RouteTunnel {
			continue
		}
		wantRules[r.Table] = r.Mark
		errs = append(errs, syncTable(r, ifaceUp[r.Iface]))
	}
	errs = append(errs, syncRules(wantRules))
	return errors.Join(errs...)
}

func syncTable(r *engine.Route, up bool) error {
	var want []*netlink.Route
	for _, fam := range families {
		want = append(want, &netlink.Route{
			Family:   fam,
			Table:    r.Table,
			Type:     unix.RTN_UNREACHABLE,
			Dst:      defaultDst(fam),
			Priority: UnreachableMetric,
		})
	}
	if up {
		link, err := netlink.LinkByName(r.Iface)
		if err != nil {
			return err
		}
		for _, pfx := range r.AllowedIPs {
			if (pfx.Addr().Is4() && !r.V4) || (pfx.Addr().Is6() && (!r.V6 || !haveFamily(netlink.FAMILY_V6))) {
				continue // no source address of that family: keep it unreachable
			}
			want = append(want, &netlink.Route{
				LinkIndex: link.Attrs().Index,
				Type:      unix.RTN_UNICAST,
				Table:     r.Table,
				Dst:       ipnet(pfx),
				Scope:     netlink.SCOPE_LINK,
			})
		}
	}
	for _, rt := range want {
		if err := netlink.RouteReplace(rt); err != nil {
			return fmt.Errorf("table %d route %v: %w", r.Table, rt.Dst, err)
		}
	}
	// remove stale routes
	have, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: r.Table}, netlink.RT_FILTER_TABLE)
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
	return nil
}

func sameRoute(a netlink.Route, b *netlink.Route) bool {
	return a.Type == b.Type && a.Priority == b.Priority && a.LinkIndex == b.LinkIndex &&
		dstString(a.Dst, a.Family) == dstString(b.Dst, b.Family)
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
