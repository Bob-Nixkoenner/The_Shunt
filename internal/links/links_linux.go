package links

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/godbus/dbus/v5"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const sysNet = "/sys/class/net"

// Kind classifies an interface by its sysfs entry: "wifi", "mobile",
// "ethernet" (a physical Ethernet device, also USB) or "" for anything
// else (bridges, containers, tunnels, loopback).
func Kind(sys, name string) string {
	dir := filepath.Join(sys, name)
	if exists(filepath.Join(dir, "wireless")) || exists(filepath.Join(dir, "phy80211")) {
		return "wifi"
	}
	if b, err := os.ReadFile(filepath.Join(dir, "uevent")); err == nil && strings.Contains(string(b), "DEVTYPE=wwan") {
		return "mobile"
	}
	if !exists(filepath.Join(dir, "device")) {
		return "" // virtual
	}
	if b, err := os.ReadFile(filepath.Join(dir, "type")); err == nil && strings.TrimSpace(string(b)) == "1" {
		if b, err := os.ReadFile(filepath.Join(dir, "uevent")); err == nil && strings.Contains(string(b), "DEVTYPE=") {
			return "" // a special device type (bridge, wlan in monitor mode …)
		}
		return "ethernet"
	}
	// cellular modems without DEVTYPE (ppp, raw-ip qmi)
	if strings.HasPrefix(name, "wwan") || strings.HasPrefix(name, "ppp") {
		return "mobile"
	}
	return ""
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

// kindOf is Kind with an override: SHUNT_LINK_KINDS="cli0=ethernet,cli1=wifi"
// (tests in network namespaces, hardware sysfs gets wrong).
func kindOf(name string) string {
	for _, kv := range strings.Split(os.Getenv("SHUNT_LINK_KINDS"), ",") {
		if n, k, ok := strings.Cut(kv, "="); ok && n == name {
			return k
		}
	}
	return Kind(sysNet, name)
}

// Current returns the connected links: per kind the interface that is up
// and has a default route in the main table (lowest metric wins).
func Current() State {
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return State{}
	}
	byIndex := map[int]*candidate{}
	for _, rt := range routes {
		if !isDefault(rt) || rt.LinkIndex == 0 {
			continue
		}
		c := byIndex[rt.LinkIndex]
		if c == nil {
			l, err := netlink.LinkByIndex(rt.LinkIndex)
			if err != nil || l.Attrs().Flags&unix.IFF_UP == 0 {
				continue
			}
			c = &candidate{Link: Link{Name: l.Attrs().Name, Index: rt.LinkIndex, Kind: kindOf(l.Attrs().Name)}, metric: rt.Priority}
			byIndex[rt.LinkIndex] = c
		}
		if rt.Priority < c.metric {
			c.metric = rt.Priority
		}
		if rt.Gw != nil {
			c.Gateways = append(c.Gateways, rt.Gw.String())
		}
	}
	var cs []candidate
	for _, c := range byIndex {
		cs = append(cs, *c)
	}
	s := choose(cs)
	for k, l := range s {
		l.DNS = resolvedDNS(l.Index)
		s[k] = l
	}
	return s
}

func isDefault(rt netlink.Route) bool {
	if rt.Dst == nil {
		return true
	}
	ones, _ := rt.Dst.Mask.Size()
	return ones == 0
}

// resolvedDNS asks systemd-resolved which DNS servers the network gave
// this interface. Nothing (no resolved, no servers) is fine: the caller
// falls back.
func resolvedDNS(ifindex int) []netip.Addr {
	conn, err := dbus.SystemBus()
	if err != nil {
		return nil
	}
	var linkPath dbus.ObjectPath
	mgr := conn.Object("org.freedesktop.resolve1", "/org/freedesktop/resolve1")
	if err := mgr.Call("org.freedesktop.resolve1.Manager.GetLink", 0, int32(ifindex)).Store(&linkPath); err != nil {
		return nil
	}
	v, err := conn.Object("org.freedesktop.resolve1", linkPath).GetProperty("org.freedesktop.resolve1.Link.DNS")
	if err != nil {
		return nil
	}
	var servers []struct {
		Family int32
		Addr   []byte
	}
	if err := dbus.Store([]any{v.Value()}, &servers); err != nil {
		return nil
	}
	var out []netip.Addr
	for _, s := range servers {
		if a, ok := netip.AddrFromSlice(s.Addr); ok && !a.IsLinkLocalUnicast() && !a.IsLoopback() {
			out = append(out, a.Unmap())
		}
	}
	return out
}
