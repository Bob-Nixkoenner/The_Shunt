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
	"net/netip"
	"strings"
)

var cgnat = netip.MustParsePrefix("100.64.0.0/10")
var global6 = netip.MustParsePrefix("2000::/3")
var reserved4 = netip.MustParsePrefix("240.0.0.0/4")

// IsPublicV4 reports whether a is an IPv4 address that is routed on the
// internet: not private (RFC 1918), loopback, link-local, multicast, "this
// network", carrier-grade NAT (100.64.0.0/10) or reserved (240/4). The
// documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
// count as public here, so tests can use them.
func IsPublicV4(a netip.Addr) bool {
	a = a.Unmap()
	if !a.Is4() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsMulticast() || a.IsUnspecified() {
		return false
	}
	if cgnat.Contains(a) || reserved4.Contains(a) || a.As4()[0] == 0 {
		return false
	}
	return true
}

// IsPublicV6 reports whether a is a global unicast IPv6 address (2000::/3);
// ULA (fc00::/7), link-local and loopback are not. The documentation range
// 2001:db8::/32 counts as public here.
func IsPublicV6(a netip.Addr) bool {
	return a.Is6() && !a.Is4In6() && global6.Contains(a)
}

// PublicIn tells which kinds of public address addrs contain.
func PublicIn(addrs []netip.Addr) (v4, v6 bool) {
	for _, a := range addrs {
		v4 = v4 || IsPublicV4(a)
		v6 = v6 || IsPublicV6(a)
	}
	return
}

// virtual interface names that never are the uplink
var virtualPrefixes = []string{"lo", "wg", "tun", "tap", "tailscale", "docker", "veth", "br-", "virbr", "vboxnet", "vmnet", "zt"}

func virtualIface(name string) bool {
	for _, p := range virtualPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// publicAddrs checks the addresses of iface (all up, non-virtual interfaces
// when iface is empty, e.g. an IPv6-only uplink without a v4 default route).
func publicAddrs(iface string) (v4, v6 bool) {
	ifs, err := net.Interfaces()
	if err != nil {
		return
	}
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || (iface != "" && i.Name != iface) || (iface == "" && virtualIface(i.Name)) {
			continue
		}
		as, _ := i.Addrs()
		var l []netip.Addr
		for _, a := range as {
			if n, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(n.IP); ok {
					l = append(l, ip)
				}
			}
		}
		a4, a6 := PublicIn(l)
		v4, v6 = v4 || a4, v6 || a6
	}
	return
}

// WithPublic fills PublicV4/PublicV6 of info from the uplink's addresses.
func WithPublic(info Info) Info {
	info.PublicV4, info.PublicV6 = publicAddrs(info.Iface)
	return info
}

// Info describes the current uplink. Empty fields are unknown.
type Info struct {
	Iface      string `json:"iface,omitempty"`
	SSID       string `json:"ssid,omitempty"`
	GatewayIP  string `json:"gateway_ip,omitempty"`
	GatewayMAC string `json:"gateway_mac,omitempty"`
	// PublicV4 / PublicV6: the uplink has an address that is neither
	// private, link-local, loopback nor carrier-grade NAT (v4), or a global
	// unicast address (v6): the machine is directly reachable from the
	// internet unless a firewall stops it. They are not part of Key.
	PublicV4 bool `json:"public_v4,omitempty"`
	PublicV6 bool `json:"public_v6,omitempty"`
	// OSProfile: the system's own rating of the network ("public",
	// "private", "domain"; Windows network profile). "" = unknown. Only a
	// hint, see ClassHint; it is not part of Key.
	OSProfile string `json:"os_profile,omitempty"`
}

// Exposure is the pair of public-address flags, for change detection.
func (i Info) Exposure() string {
	b := func(x bool) string {
		if x {
			return "1"
		}
		return "0"
	}
	return b(i.PublicV4) + b(i.PublicV6)
}

// Key identifies the network for change detection.
func (i Info) Key() string { return i.Iface + "|" + i.SSID + "|" + i.GatewayMAC }
