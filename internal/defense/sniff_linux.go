package defense

import (
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Sensors runs the passive and periodic checks of one network: ARP/NDP
// gateway watch (netlink neighbour events), rogue DHCP server (AF_PACKET,
// needs CAP_NET_RAW), DNS comparison and evil-twin check. Everything it
// finds goes to Manager.Report. Findings never contain SSIDs or MACs.
type Sensors struct {
	M     *Manager
	Log   *slog.Logger
	DNS   DNSCheck
	Twins *TwinStore
	// Mark is set on the DNS query sockets (the "bypass" mark: main table,
	// physical link).
	Mark uint32

	mu     sync.Mutex
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// SetEnv (re)starts the sensors for the network now in use.
func (s *Sensors) SetEnv(env Env) {
	s.Stop()
	ctx, cancel := context.WithCancel(context.Background())
	s.mu.Lock()
	s.cancel = cancel
	s.mu.Unlock()
	if env.Iface == "" {
		return
	}
	run := func(f func()) {
		s.wg.Add(1)
		go func() { defer s.wg.Done(); f() }()
	}
	run(func() { s.neighbours(ctx, env) })
	run(func() { s.dhcp(ctx, env) })
	run(func() { s.once(ctx, env) })
}

// Stop ends all sensors and waits for them.
func (s *Sensors) Stop() {
	s.mu.Lock()
	c := s.cancel
	s.cancel = nil
	s.mu.Unlock()
	if c != nil {
		c()
	}
	s.wg.Wait()
}

func (s *Sensors) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func (s *Sensors) emit(feat string, ev Event) {
	if s.M.Watching(feat) {
		s.M.Report(ev)
	}
}

// once runs the checks that happen when a network is joined.
func (s *Sensors) once(ctx context.Context, env Env) {
	if s.Twins != nil && s.Twins.Check(env.SSID, env.GatewayMAC) {
		s.emit(FeatEvilTwin, TwinEvent())
	}
	select { // let the link settle before asking questions
	case <-ctx.Done():
		return
	case <-time.After(3 * time.Second):
	}
	if !s.M.Watching(FeatDNS) {
		return
	}
	c := s.DNS
	if s.Mark != 0 {
		mark := s.Mark
		c.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second, Control: func(_, _ string, rc syscall.RawConn) error {
				var serr error
				err := rc.Control(func(fd uintptr) {
					serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark))
				})
				if err != nil {
					return err
				}
				return serr
			}}
			return d.DialContext(ctx, network, addr)
		}
	}
	qctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	for _, ev := range c.Run(qctx, env) {
		s.emit(FeatDNS, ev)
	}
}

// neighbours follows ARP/NDP entries of the interface and watches the
// gateway's MAC.
func (s *Sensors) neighbours(ctx context.Context, env Env) {
	if env.GatewayIP == "" {
		return
	}
	link, err := netlink.LinkByName(env.Iface)
	if err != nil {
		return
	}
	idx := link.Attrs().Index
	gw := newGWWatch(env.GatewayIP, env.GatewayMAC)
	feed := func(ip net.IP, mac net.HardwareAddr, state int) {
		if len(mac) == 0 || state&(netlink.NUD_FAILED|netlink.NUD_INCOMPLETE) != 0 {
			return
		}
		a, ok := netip.AddrFromSlice(ip)
		if !ok {
			return
		}
		if ev, hit := gw.Feed(a, mac.String()); hit {
			s.emit(FeatARP, ev)
		}
	}
	ch := make(chan netlink.NeighUpdate, 64)
	done := make(chan struct{})
	defer close(done)
	if err := netlink.NeighSubscribeWithOptions(ch, done, netlink.NeighSubscribeOptions{
		ErrorCallback: func(error) {},
	}); err != nil {
		s.log().Debug("defense: no neighbour events", "err", err)
		return
	}
	if ns, err := netlink.NeighList(idx, netlink.FAMILY_ALL); err == nil {
		for _, n := range ns {
			feed(n.IP, n.HardwareAddr, n.State)
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case u, ok := <-ch:
			if !ok {
				return
			}
			if u.LinkIndex == idx && u.Type == unix.RTM_NEWNEIGH {
				feed(u.IP, u.HardwareAddr, u.State)
			}
		}
	}
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// dhcpFilter is a classic BPF program: IPv4, UDP, not fragmented, source
// port 67, destination port 68. A SOCK_DGRAM packet socket sees the packet
// from the IP header on.
var dhcpFilter = []unix.SockFilter{
	{Code: 0x30, K: 9},             // ldb [9]  protocol
	{Code: 0x15, Jf: 8, K: 17},     // jeq UDP else drop
	{Code: 0x28, K: 6},             // ldh [6]  flags/fragment offset
	{Code: 0x45, Jt: 6, K: 0x1fff}, // jset fragment offset -> drop
	{Code: 0xb1, K: 0},             // ldxb 4*([0]&0xf)
	{Code: 0x48, K: 0},             // ldh [x+0] source port
	{Code: 0x15, Jf: 3, K: 67},     // jeq 67 else drop
	{Code: 0x48, K: 2},             // ldh [x+2] destination port
	{Code: 0x15, Jf: 1, K: 68},     // jeq 68 else drop
	{Code: 0x06, K: 262144},        // accept
	{Code: 0x06, K: 0},             // drop
}

// dhcp listens for DHCP replies on the interface and reports a second
// server. Passive only: it sends nothing.
func (s *Sensors) dhcp(ctx context.Context, env Env) {
	link, err := netlink.LinkByName(env.Iface)
	if err != nil {
		return
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_IP)))
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			s.log().Debug("defense: DHCP watch needs CAP_NET_RAW")
		}
		return
	}
	defer unix.Close(fd)
	prog := unix.SockFprog{Len: uint16(len(dhcpFilter)), Filter: &dhcpFilter[0]}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &prog); err != nil {
		return // without the filter every IPv4 packet would be copied here
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_IP), Ifindex: link.Attrs().Index}); err != nil {
		return
	}
	tv := unix.NsecToTimeval(int64(time.Second))
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	w := newDHCPWatch()
	buf := make([]byte, 2048)
	for ctx.Err() == nil {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			continue // timeout or EINTR: look at ctx again
		}
		if n < 28 || buf[0]>>4 != 4 {
			continue
		}
		ihl := int(buf[0]&0xf) * 4
		if n < ihl+8 || binary.BigEndian.Uint16(buf[ihl:]) != 67 {
			continue
		}
		srv, ok := ParseDHCPReply(buf[ihl+8 : n])
		if !ok {
			continue
		}
		if ev, hit := w.Feed(srv); hit {
			s.emit(FeatDHCP, ev)
		}
	}
}
