package wfp

import (
	"net/netip"
	"sort"
)

// The quiet mode (Windows counterpart of the Linux quiet_out chain): outgoing
// discovery traffic is dropped. The rules are described here without any
// Windows types so they can be tested everywhere; quiet_windows.go turns them
// into filters at the ALE connect layers.

// Discovery ports of a quiet machine: NetBIOS name/datagram, KDE Connect,
// SSDP, mDNS, LLMNR, Syncthing local discovery (UDP) and KDE Connect (TCP).
var (
	QuietUDPPorts = []uint16{137, 138, 1716, 1900, 5353, 5355, 21027}
	QuietTCPPorts = []uint16{1716}
)

// QuietRule is one filter: Permit (else drop) packets of IP protocol Proto
// (6 TCP, 17 UDP, 58 ICMPv6) to RemotePort (ICMP type for 58; 0 = any), to
// addresses inside Prefix (invalid = any).
type QuietRule struct {
	V6         bool
	Permit     bool
	Proto      uint8
	RemotePort uint16
	Prefix     netip.Prefix
}

// QuietWeight is the weight (0..15) of a quiet filter. In the own sublayer
// the permits (15) come before the drops (10). The boot-time copies share the
// default sublayer with the kill switch's boot-time copies (weights: service
// and DNS 14/15, loopback 13, DHCP/ND/tunnel 12, LAN 11, block 0), where the
// higher weight wins: the drops (13) must beat its LAN permit (multicast,
// broadcast) and its DHCP permit (255.255.255.255), the own DHCP/ND permits
// (15) the drops.
func QuietWeight(r QuietRule, boot bool) uint8 {
	switch {
	case r.Permit:
		return 15
	case boot:
		return 13
	}
	return 10
}

// QuietRules returns the filters in the order they are weighed: first the
// permits (DHCP, DHCPv6 and IPv6 neighbour/router discovery), then the drops.
// broadcasts are subnet broadcast addresses (IPv4) to drop as well.
func QuietRules(broadcasts []netip.Addr) []QuietRule {
	var r []QuietRule
	r = append(r, QuietRule{Permit: true, Proto: 17, RemotePort: 67})
	r = append(r, QuietRule{V6: true, Permit: true, Proto: 17, RemotePort: 547})
	for t := uint16(133); t <= 137; t++ {
		r = append(r, QuietRule{V6: true, Permit: true, Proto: 58, RemotePort: t})
	}
	for _, v6 := range []bool{false, true} {
		for _, p := range QuietUDPPorts {
			r = append(r, QuietRule{V6: v6, Proto: 17, RemotePort: p})
		}
		for _, p := range QuietTCPPorts {
			r = append(r, QuietRule{V6: v6, Proto: 6, RemotePort: p})
		}
	}
	r = append(r,
		QuietRule{Prefix: netip.MustParsePrefix("224.0.0.0/4")},
		QuietRule{Prefix: netip.MustParsePrefix("255.255.255.255/32")},
		QuietRule{V6: true, Prefix: netip.MustParsePrefix("ff00::/8")})
	bs := append([]netip.Addr(nil), broadcasts...)
	sort.Slice(bs, func(i, j int) bool { return bs[i].Less(bs[j]) })
	for i, b := range bs {
		if !b.Is4() || (i > 0 && bs[i-1] == b) || b == netip.MustParseAddr("255.255.255.255") {
			continue
		}
		r = append(r, QuietRule{Prefix: netip.PrefixFrom(b, 32)})
	}
	return r
}

// BroadcastAddrs returns the IPv4 subnet broadcast addresses of the given
// interface addresses (prefixes /8../30 only).
func BroadcastAddrs(prefixes []netip.Prefix) []netip.Addr {
	var out []netip.Addr
	for _, p := range prefixes {
		a := p.Addr().Unmap()
		if !a.Is4() || p.Bits() > 30 || p.Bits() < 8 {
			continue
		}
		b := a.As4()
		v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
		v |= uint32(0xffffffff) >> uint(p.Bits())
		out = append(out, netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}))
	}
	return out
}
