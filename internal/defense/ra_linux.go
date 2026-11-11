package defense

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// raFilter: IPv6 (from the IPv6 header on), then accept
//   - ICMPv6 (58) type 134 (router advertisement) when it follows the header
//     directly,
//   - next header 44 (fragment), so an advertisement hidden behind a
//     fragment header is looked at in user space,
//   - UDP (17) from port 547 to port 546 (DHCPv6 server to client).
//
// Advertisements behind other extension headers (hop-by-hop, routing,
// destination options) are not seen; that blind spot is listed in the docs.
var raFilter = []unix.SockFilter{
	{Code: 0x30, K: 6},                 // 0 ldb [6] next header
	{Code: 0x15, Jf: 2, K: 58},         // 1 jeq ICMPv6 else 4
	{Code: 0x30, K: 40},                // 2 ldb [40] ICMPv6 type
	{Code: 0x15, Jt: 6, Jf: 7, K: 134}, // 3 jeq RA -> accept else drop
	{Code: 0x15, Jt: 5, K: 44},         // 4 jeq fragment -> accept else 5
	{Code: 0x15, Jf: 5, K: 17},         // 5 jeq UDP else drop
	{Code: 0x28, K: 40},                // 6 ldh [40] source port
	{Code: 0x15, Jf: 3, K: 547},        // 7 jeq 547 else drop
	{Code: 0x28, K: 42},                // 8 ldh [42] destination port
	{Code: 0x15, Jf: 1, K: 546},        // 9 jeq 546 else drop
	{Code: 0x06, K: 262144},            // 10 accept
	{Code: 0x06, K: 0},                 // 11 drop
}

// routerAdverts listens for router advertisements and DHCPv6 server
// messages on the interface. Passive only. Needs CAP_NET_RAW.
func (s *Sensors) routerAdverts(ctx context.Context, env Env) {
	link, err := netlink.LinkByName(env.Iface)
	if err != nil {
		return
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_IPV6)))
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			s.log().Debug("defense: router advertisement watch needs CAP_NET_RAW")
		}
		return
	}
	defer unix.Close(fd)
	prog := unix.SockFprog{Len: uint16(len(raFilter)), Filter: &raFilter[0]}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &prog); err != nil {
		return
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_IPV6), Ifindex: link.Attrs().Index}); err != nil {
		return
	}
	tv := unix.NsecToTimeval(int64(time.Second))
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	w := newRAWatch()
	buf := make([]byte, 2048)
	for ctx.Err() == nil {
		n, from, err := unix.Recvfrom(fd, buf, 0)
		if err != nil || n < 40 {
			continue
		}
		mac := ""
		if ll, ok := from.(*unix.SockaddrLinklayer); ok {
			if ll.Pkttype == unix.PACKET_OUTGOING {
				continue // our own packets
			}
			if ll.Halen == 6 {
				mac = net.HardwareAddr(ll.Addr[:6]).String()
			}
		}
		if ra, ok := ParseRA(buf[:n], mac); ok {
			for _, ev := range w.Feed(ra) {
				s.emit(FeatRogueRA, ev)
			}
		} else if r, ok := ParseDHCPv6(buf[:n]); ok {
			for _, ev := range w.FeedDHCPv6(r) {
				s.emit(FeatRogueRA, ev)
			}
		}
	}
}
