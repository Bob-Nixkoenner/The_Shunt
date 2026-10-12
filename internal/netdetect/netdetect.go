// Package netdetect tells which network the machine is on: the Wi-Fi name
// (SSID) and the MAC address of the default gateway. Network profiles
// ([[network]] in the config) match on these.
//
// An SSID is trivial to fake (anyone can call a hotspot "FritzBox"); the
// gateway MAC is harder to guess. Profiles that relax protection should
// match on both.
package netdetect

import (
	"net"
	"sort"
	"strings"

	"github.com/mdlayher/wifi"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Info describes the current uplink. Empty fields are unknown.
type Info struct {
	Iface      string `json:"iface,omitempty"`
	SSID       string `json:"ssid,omitempty"`
	GatewayIP  string `json:"gateway_ip,omitempty"`
	GatewayMAC string `json:"gateway_mac,omitempty"`
}

// Key identifies the network for change detection.
func (i Info) Key() string { return i.Iface + "|" + i.SSID + "|" + i.GatewayMAC }

// Current looks at the default IPv4 route of the main table and its gateway.
func Current() Info {
	var info Info
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return info
	}
	var defs []netlink.Route
	for _, r := range routes {
		if (r.Dst == nil || r.Dst.IP.IsUnspecified() && isZeroMask(r.Dst.Mask)) && r.Gw != nil {
			defs = append(defs, r)
		}
	}
	if len(defs) == 0 {
		return info
	}
	sort.Slice(defs, func(a, b int) bool { return defs[a].Priority < defs[b].Priority })
	def := defs[0]
	link, err := netlink.LinkByIndex(def.LinkIndex)
	if err != nil {
		return info
	}
	info.Iface = link.Attrs().Name
	info.GatewayIP = def.Gw.String()
	if neighs, err := netlink.NeighList(def.LinkIndex, netlink.FAMILY_V4); err == nil {
		for _, n := range neighs {
			if n.IP.Equal(def.Gw) && len(n.HardwareAddr) > 0 && n.State&(netlink.NUD_FAILED|netlink.NUD_INCOMPLETE) == 0 {
				info.GatewayMAC = strings.ToLower(n.HardwareAddr.String())
			}
		}
	}
	info.SSID = ssid(info.Iface)
	return info
}

func isZeroMask(m net.IPMask) bool {
	ones, _ := m.Size()
	return ones == 0
}

func ssid(iface string) string {
	c, err := wifi.New()
	if err != nil {
		return ""
	}
	defer c.Close()
	ifis, err := c.Interfaces()
	if err != nil {
		return ""
	}
	for _, ifi := range ifis {
		if ifi.Name != iface {
			continue
		}
		if bss, err := c.BSS(ifi); err == nil && bss != nil {
			return bss.SSID
		}
	}
	return ""
}
