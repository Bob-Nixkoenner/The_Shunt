package tunnel

import (
	"hash/fnv"
	"net/netip"

	"github.com/Bob-Nixkoenner/the_shunt/internal/tsconf"
)

// TailscaleSpec describes a Tailscale/Headscale tunnel.
//
// tailscaled runs in a network namespace of its own, connected to the host
// by a veth pair: tailscaled's routing rules, firewall rules and routes stay
// there and cannot disturb Shunt's. Shunt's interface (Iface) is the host
// end of the pair; the route of the tunnel points at the namespace's end
// (TailscaleAddrs) and tailscaled's packets to the tailnet arrive again on
// Iface, where the firewall marks them like any other encrypted packet.
type TailscaleSpec struct {
	Name     string
	Iface    string
	Conf     *tsconf.Config
	RunDir   string // sockets and pid file
	StateDir string // tailscaled's node key and settings (survive restarts)
}

// TailscaleAddrs returns the two ends of the tunnel's veth link (a /30 from
// 198.18.0.0/15, the benchmarking range nobody uses): host, namespace.
func TailscaleAddrs(name string) (host, peer netip.Addr) {
	h := fnv.New32a()
	_, _ = h.Write([]byte(name))
	base := netip.MustParseAddr("198.18.0.0").As4()
	n := (h.Sum32() % 32768) * 4 // 198.18.0.0 + 2^15 /30 blocks = 198.18.0.0/15
	v := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	v += n
	at := func(off uint32) netip.Addr {
		x := v + off
		return netip.AddrFrom4([4]byte{byte(x >> 24), byte(x >> 16), byte(x >> 8), byte(x)})
	}
	return at(1), at(2)
}

// TailscaleDNS is tailscaled's own resolver (MagicDNS), reachable through
// the tunnel.
var TailscaleDNS = netip.MustParseAddr("100.100.100.100")
