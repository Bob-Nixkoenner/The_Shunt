package daemon

import (
	"net"
	"net/netip"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestStrayFlow(t *testing.T) {
	m := strayFlow{
		local: map[netip.Addr]bool{netip.MustParseAddr("192.0.2.10"): true, netip.MustParseAddr("2001:db8::10"): true},
		keep:  []netip.Prefix{netip.MustParsePrefix("203.0.113.5/32")},
	}
	flow := func(proto uint8, src, dst string) *netlink.ConntrackFlow {
		return &netlink.ConntrackFlow{Forward: netlink.IPTuple{Protocol: proto, SrcIP: net.ParseIP(src), DstIP: net.ParseIP(dst)}}
	}
	for _, c := range []struct {
		name string
		f    *netlink.ConntrackFlow
		want bool
	}{
		{"own v6 SYN to a stranger", flow(unix.IPPROTO_TCP, "2001:db8::10", "2001:db8:ffff::1"), true},
		{"own v4 UDP to a stranger", flow(unix.IPPROTO_UDP, "192.0.2.10", "198.51.100.1"), true},
		{"to a relay", flow(unix.IPPROTO_TCP, "192.0.2.10", "203.0.113.5"), false},
		{"loopback", flow(unix.IPPROTO_TCP, "192.0.2.10", "127.0.0.1"), false},
		{"forwarded (gateway)", flow(unix.IPPROTO_TCP, "192.0.2.77", "198.51.100.1"), false},
		{"ICMP", flow(unix.IPPROTO_ICMP, "192.0.2.10", "198.51.100.1"), false},
	} {
		if got := m.MatchConntrackFlow(c.f); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}
