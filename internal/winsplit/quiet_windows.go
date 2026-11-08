//go:build windows

package winsplit

import (
	"net"
	"net/netip"

	"github.com/Bob-Nixkoenner/the_shunt/internal/winsplit/wfp"
)

// EnableQuiet drops outgoing discovery traffic (NetBIOS, LLMNR, mDNS, SSDP,
// KDE Connect, Syncthing, multicast, broadcast; DHCP and IPv6 neighbour
// discovery stay) with persistent WFP filters. The subnet broadcast addresses
// of the machine's current interfaces are included.
func EnableQuiet() error { return wfp.EnableQuiet(localBroadcasts()) }

// EnableQuietBoot installs the same filters without subnet broadcasts (they
// are not known yet); used to cover the time before the service runs.
func EnableQuietBoot() error { return wfp.EnableQuiet(nil) }

// DisableQuiet removes the quiet-mode filters (also one left by an earlier
// run). Safe to call when nothing is installed.
func DisableQuiet() { _ = wfp.DisableQuiet() }

func localBroadcasts() []netip.Addr {
	var ps []netip.Prefix
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if p, ok := netip.AddrFromSlice(ipn.IP); ok {
				ones, _ := ipn.Mask.Size()
				ps = append(ps, netip.PrefixFrom(p.Unmap(), ones))
			}
		}
	}
	return wfp.BroadcastAddrs(ps)
}
