//go:build linux

package mobile

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	nicID      = 1
	udpIdle    = 2 * time.Minute
	dnsIdle    = 15 * time.Second // a DNS flow (one source port) ends after this
	dialTimout = 10 * time.Second
)

var errBlocked = errors.New("blocked")

// newStack terminates the TUN: every TCP connection and UDP flow the apps
// open lands in a forwarder below.
func newStack(fd int, mtu uint32, e *Engine) (*stack.Stack, error) {
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, fmt.Errorf("tun fd: %w", err)
	}
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	ep, err := fdbased.New(&fdbased.Options{FDs: []int{fd}, MTU: mtu, PacketDispatchMode: fdbased.Readv})
	if err != nil {
		return nil, fmt.Errorf("tun endpoint: %v", err)
	}
	if terr := s.CreateNIC(nicID, ep); terr != nil {
		return nil, fmt.Errorf("nic: %v", terr)
	}
	// accept packets for any destination and answer from any address
	s.SetPromiscuousMode(nicID, true)
	s.SetSpoofing(nicID, true)
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})
	sack := tcpip.TCPSACKEnabled(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack)

	tf := tcp.NewForwarder(s, 0, 4096, e.handleTCP)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tf.HandlePacket)
	uf := udp.NewForwarder(s, e.handleUDP)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, uf.HandlePacket)
	return s, nil
}

func addrPort(a tcpip.Address, port uint16) netip.AddrPort {
	ip, _ := netip.AddrFromSlice(a.AsSlice())
	return netip.AddrPortFrom(ip.Unmap(), port)
}

// flow is one connection as the app sees it.
type flow struct {
	proto    int // 6 TCP, 17 UDP
	src, dst netip.AddrPort
	uid      int
	route    string
}

func (e *Engine) newFlow(proto int, id stack.TransportEndpointID) *flow {
	f := &flow{proto: proto, src: addrPort(id.RemoteAddress, id.RemotePort), dst: addrPort(id.LocalAddress, id.LocalPort), uid: -1}
	if e.p != nil {
		f.uid = e.p.OwnerUid(proto, f.src.Addr().String(), int(f.src.Port()), f.dst.Addr().String(), int(f.dst.Port()))
	}
	f.route = e.routeFor(f.uid)
	e.flows.Add(1)
	return f
}

func (f *flow) isDNS(e *Engine) bool { return f.dst.Addr() == e.dns && f.dst.Port() == 53 }

// dial opens the outgoing side of a flow on its route. Unknown or broken
// tunnels block: nothing falls back to direct.
func (e *Engine) dial(ctx context.Context, f *flow) (net.Conn, error) {
	dst := f.dst
	if f.route == RouteBlock {
		return nil, errBlocked
	}
	if f.route == RouteDirect {
		if f.isDNS(e) {
			dst = netip.AddrPortFrom(e.direct, 53)
		}
		var d net.Dialer
		return d.DialContext(ctx, map[int]string{6: "tcp", 17: "udp"}[f.proto], dst.String())
	}
	t := e.tunnels[strings.TrimPrefix(f.route, tunnelPref)]
	if t == nil || t.net == nil {
		return nil, fmt.Errorf("tunnel %s is not up", f.route)
	}
	if f.isDNS(e) {
		dst = netip.AddrPortFrom(t.dns, 53)
	}
	if (dst.Addr().Is4() && !t.v4) || (dst.Addr().Is6() && !t.v6) {
		return nil, fmt.Errorf("%s has no address of this IP family", f.route)
	}
	if f.proto == 6 {
		return t.net.DialContextTCPAddrPort(ctx, dst)
	}
	return t.net.DialUDPAddrPort(netip.AddrPort{}, dst)
}

func (e *Engine) handleTCP(r *tcp.ForwarderRequest) {
	f := e.newFlow(6, r.ID())
	ctx, cancel := context.WithTimeout(context.Background(), dialTimout)
	out, err := e.dial(ctx, f)
	cancel()
	if err != nil {
		if errors.Is(err, errBlocked) {
			e.blocked.Add(1)
		}
		r.Complete(true) // RST: the app sees "connection refused" at once
		return
	}
	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		out.Close()
		r.Complete(true)
		return
	}
	r.Complete(false)
	in := gonet.NewTCPConn(&wq, ep)
	relayTCP(in, out)
}

type closeWriter interface{ CloseWrite() error }

func relayTCP(a, b net.Conn) {
	var wg sync.WaitGroup
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		io.Copy(dst, src)
		if cw, ok := dst.(closeWriter); ok {
			cw.CloseWrite()
		} else {
			dst.Close()
		}
	}
	wg.Add(2)
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
	a.Close()
	b.Close()
}

func (e *Engine) handleUDP(r *udp.ForwarderRequest) {
	f := e.newFlow(17, r.ID())
	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		return
	}
	in := gonet.NewUDPConn(&wq, ep)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), dialTimout)
		out, err := e.dial(ctx, f)
		cancel()
		if err != nil {
			if errors.Is(err, errBlocked) {
				e.blocked.Add(1)
			}
			in.Close()
			return
		}
		if f.isDNS(e) {
			e.relayDNS(f, in, out)
			return
		}
		relayUDP(in, out, udpIdle)
	}()
}

// relayUDP copies datagrams both ways until the flow is idle.
func relayUDP(in, out net.Conn, idle time.Duration) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		buf := make([]byte, 65535)
		for {
			src.SetReadDeadline(time.Now().Add(idle))
			n, err := src.Read(buf)
			if err != nil {
				break
			}
			if _, err := dst.Write(buf[:n]); err != nil {
				break
			}
		}
		done <- struct{}{}
	}
	go cp(out, in)
	go cp(in, out)
	<-done
	in.Close()
	out.Close()
	<-done
}

// relayDNS is relayUDP for queries to the VPN's DNS address, with the DNS
// filter: blocked names are answered NXDOMAIN right here.
func (e *Engine) relayDNS(f *flow, in, out net.Conn) {
	done := make(chan struct{})
	go func() { // answers back to the app
		buf := make([]byte, 65535)
		for {
			out.SetReadDeadline(time.Now().Add(dnsIdle))
			n, err := out.Read(buf)
			if err != nil {
				break
			}
			in.Write(buf[:n])
		}
		close(done)
	}()
	buf := make([]byte, 65535)
	for {
		in.SetReadDeadline(time.Now().Add(dnsIdle))
		n, err := in.Read(buf)
		if err != nil {
			break
		}
		var q dns.Msg
		if q.Unpack(buf[:n]) == nil && len(q.Question) == 1 {
			if list := e.blockedName(f.uid, q.Question[0].Name); list != "" {
				e.dnsBlocked.Add(1)
				r := new(dns.Msg)
				r.SetRcode(&q, dns.RcodeNameError)
				if b, err := r.Pack(); err == nil {
					in.Write(b)
				}
				continue
			}
		}
		if _, err := out.Write(buf[:n]); err != nil {
			break
		}
	}
	in.Close()
	out.Close()
	<-done
}
