package wfp

import "net/netip"

// The quiet mode (Windows counterpart of the Linux quiet_out chain): outgoing
// discovery traffic is dropped. The rules are described here without any
// Windows types so they can be tested everywhere; quiet_windows.go turns them
// into filters.
//
// The set does not depend on the network: subnet broadcasts (10.77.0.255) are
// matched by the destination address type the stack itself determines
// (FWPM_CONDITION_IP_DESTINATION_ADDRESS_TYPE = broadcast), like the Linux
// "fib daddr type broadcast". An earlier version listed the subnet broadcast
// addresses of the current interfaces; the boot set installed at shutdown had
// none of them (D05: NBNS to 10.77.0.255 after a restart).
//
// Every rule is installed at two layers. ALE_AUTH_CONNECT only sees the first
// packet of a flow: what belongs to a flow authorized before the filters were
// there, or to the one global flow of inbound multicast/broadcast (NBNS on
// local port 137, LLMNR on 5355 also receive), is not classified there again
// (D05: LLMNR to ff02::1:3 and NBNS went out although the port filters were
// loaded). OUTBOUND_TRANSPORT is classified for every outgoing packet.

// Discovery ports of a quiet machine: NetBIOS name/datagram, KDE Connect,
// SSDP, mDNS, LLMNR, WS-Discovery, Syncthing local discovery (UDP) and KDE
// Connect (TCP).
var (
	QuietUDPPorts = []uint16{137, 138, 1716, 1900, 3702, 5353, 5355, 21027}
	QuietTCPPorts = []uint16{1716}
)

// QuietRule is one filter: Permit (else drop) packets of IP protocol Proto
// (6 TCP, 17 UDP, 58 ICMPv6; 0 = any) to RemotePort (ICMP type for 58;
// 0 = any), to addresses inside Prefix (invalid = any), and with
// DestBroadcast only to addresses the stack classifies as broadcast.
type QuietRule struct {
	V6            bool
	Permit        bool
	Proto         uint8
	RemotePort    uint16
	Prefix        netip.Prefix
	DestBroadcast bool
}

// QuietLayer is the WFP layer a quiet filter sits at.
type QuietLayer uint8

const (
	QuietLayerConnect   QuietLayer = iota // FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6
	QuietLayerTransport                   // FWPM_LAYER_OUTBOUND_TRANSPORT_V4/V6
)

func (l QuietLayer) String() string {
	if l == QuietLayerTransport {
		return "outbound transport"
	}
	return "ALE connect"
}

// QuietLayers are the layers every rule is installed at.
var QuietLayers = []QuietLayer{QuietLayerConnect, QuietLayerTransport}

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

// QuietRules returns the rules in the order they are weighed: first the
// permits (DHCP, DHCPv6 and IPv6 neighbour/router discovery), then the drops.
func QuietRules() []QuietRule {
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
		QuietRule{DestBroadcast: true}, // subnet broadcasts, whatever the network
		QuietRule{V6: true, Prefix: netip.MustParsePrefix("ff00::/8")})
	return r
}

// QuietMaxIndex bounds the filter indexes: the persistent keys
// 5e4a7f00..5e4a7f7f stay below the kill switch's boot-time keys (5e4a8000),
// the boot-time ones 5e4a8100..5e4a817f.
const QuietMaxIndex = 128

// QuietFilter is one installed filter: a rule at a layer, persistent (own
// provider and sublayer) or its boot-time copy (default sublayer, no
// provider). Index is added to Data1 of the persistent key base (quBase) or
// the boot-time one (quBootBase).
type QuietFilter struct {
	Rule   QuietRule
	Layer  QuietLayer
	Boot   bool
	Index  uint32
	Weight uint8
	Name   string
}

// QuietFilters returns every filter the quiet mode installs: each rule at
// each layer, persistent and as a boot-time copy under the same index.
func QuietFilters() []QuietFilter {
	var out []QuietFilter
	var next uint32
	for _, r := range QuietRules() {
		for _, l := range QuietLayers {
			fam := "IPv4"
			if r.V6 {
				fam = "IPv6"
			}
			name := "Quiet: drop discovery (" + fam + ", " + l.String() + ")"
			if r.Permit {
				name = "Quiet: permit DHCP/ND (" + fam + ", " + l.String() + ")"
			}
			for _, boot := range []bool{false, true} {
				out = append(out, QuietFilter{Rule: r, Layer: l, Boot: boot, Index: next, Weight: QuietWeight(r, boot), Name: name})
			}
			next++
		}
	}
	return out
}
