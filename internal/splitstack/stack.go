package splitstack

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
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
func newStack(ep stack.LinkEndpoint, e *Engine) (*stack.Stack, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	// handlers and options first, then packets: the NIC starts disabled,
	// otherwise the link delivers into a half-configured stack (data race)
	sack := tcpip.TCPSACKEnabled(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack)
	tf := tcp.NewForwarder(s, 0, 4096, e.handleTCP)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tf.HandlePacket)
	uf := udp.NewForwarder(s, func(r *udp.ForwarderRequest) bool { e.handleUDP(r); return true })
	s.SetTransportProtocolHandler(udp.ProtocolNumber, uf.HandlePacket)
	if terr := s.CreateNICWithOptions(nicID, ep, stack.NICOptions{Disabled: true}); terr != nil {
		return nil, fmt.Errorf("nic: %v", terr)
	}
	// accept packets for any destination and answer from any address
	s.SetPromiscuousMode(nicID, true)
	s.SetSpoofing(nicID, true)
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})
	if terr := s.EnableNIC(nicID); terr != nil {
		return nil, fmt.Errorf("nic: %v", terr)
	}
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
	app      string // owner, "" = unknown
	pinned   string // route the owner was started in ("" = none, see Pinned)
	route    string
	pass     bool // direct only because of a pass (override): cut when it ends
	// byDefault: on the default route (no app or destination rule); cut
	// when a network profile changes that route
	byDefault bool
	// viaLink: the route was link:<kind> (resolved to direct or block when
	// the flow started); cut when the kind of network changes
	viaLink string
	// dnsTried: the DNS server a query to the VPN's DNS address was sent to
	dnsTried netip.Addr
}

func (e *Engine) newFlow(proto int, id stack.TransportEndpointID) *flow {
	f := &flow{proto: proto, src: addrPort(id.RemoteAddress, id.RemotePort), dst: addrPort(id.LocalAddress, id.LocalPort)}
	if e.o.Owner != nil {
		f.pinned, f.app = splitPinned(e.o.Owner(proto, f.src, f.dst))
	}
	normal, byDefault := e.routeFor(f.app, f.pinned, proto, f.dst, f.isDNS(e))
	f.byDefault = byDefault
	normal, f.viaLink = e.resolveLink(normal)
	f.route = e.ov.Route(normal, time.Now())
	f.pass = f.route == RouteDirect && normal != RouteDirect
	e.flows.Add(1)
	return f
}

// track registers a running flow so panic (and the end of a pass) can cut
// it; the returned func unregisters it.
func (e *Engine) track(f *flow, conns ...net.Conn) func() {
	e.actMu.Lock()
	if e.active == nil {
		e.active = map[*flow][]net.Conn{}
	}
	e.active[f] = conns
	e.actMu.Unlock()
	return func() {
		e.actMu.Lock()
		delete(e.active, f)
		e.actMu.Unlock()
	}
}

// cut closes running flows that match.
func (e *Engine) cut(match func(*flow) bool) int {
	e.actMu.Lock()
	var cs []net.Conn
	n := 0
	for f, conns := range e.active {
		if match(f) {
			cs = append(cs, conns...)
			n++
		}
	}
	e.actMu.Unlock()
	for _, c := range cs {
		c.Close()
	}
	return n
}

// resolveLink turns link:<kind> into direct (the machine is connected over
// that kind of network right now) or block (it is not): the app goes out
// over that connection only, never over another one.
func (e *Engine) resolveLink(route string) (resolved, kind string) {
	k, ok := strings.CutPrefix(route, linkPref)
	if !ok {
		return route, ""
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.link == k {
		return RouteDirect, k
	}
	return RouteBlock, k
}

func (f *flow) isDNS(e *Engine) bool { return f.dst.Addr() == e.dns && f.dst.Port() == 53 }

// dial opens the outgoing side of a flow on its route. Unknown or broken
// tunnels block: nothing falls back to direct.
func (e *Engine) dial(ctx context.Context, f *flow) (net.Conn, error) {
	return e.dialTo(ctx, f, f.dst)
}

// dialTo is dial to another destination (the DNS retries). Queries to the
// VPN's DNS address go to the first DNS server of the route.
func (e *Engine) dialTo(ctx context.Context, f *flow, dst netip.AddrPort) (net.Conn, error) {
	if f.route == RouteBlock {
		return nil, errBlocked
	}
	toDNS := dst.Addr() == e.dns && dst.Port() == 53
	if f.route == RouteDirect {
		if toDNS {
			f.dnsTried = e.dnsServers(RouteDirect)[0]
			dst = netip.AddrPortFrom(f.dnsTried, 53)
		}
		return e.o.DialDirect(ctx, map[int]string{6: "tcp", 17: "udp"}[f.proto], dst.String())
	}
	name := strings.TrimPrefix(f.route, tunnelPref)
	t := e.tunnel(name)
	if t != nil && t.dormant {
		t = e.wake(name) // on demand: the first connection makes the tunnel
	}
	if t == nil || !t.reachable() {
		return nil, fmt.Errorf("tunnel %s is not up", f.route)
	}
	t.use()
	if toDNS {
		f.dnsTried = e.dnsServers(f.route)[0]
		dst = netip.AddrPortFrom(f.dnsTried, 53)
	}
	if v4, v6 := t.families(); (dst.Addr().Is4() && !v4) || (dst.Addr().Is6() && !v6) {
		return nil, fmt.Errorf("%s has no address of this IP family", f.route)
	}
	return t.dialAP(ctx, f.proto == 6, dst)
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
	defer e.track(f, in, out)()
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
			if f.isDNS(e) {
				refuseDNS(in) // answer at once instead of letting the app time out
			}
			in.Close()
			return
		}
		defer e.track(f, in, out)()
		if f.isDNS(e) {
			e.relayDNS(f, in, out)
			return
		}
		relayUDP(in, out, udpIdle)
	}()
}

// relayUDP copies datagrams both ways until the flow is idle in both
// directions (a one-way stream, e.g. media the app only receives, stays up).
func relayUDP(in, out net.Conn, idle time.Duration) {
	var last atomic.Int64 // unix nanos of the last datagram either way
	last.Store(time.Now().UnixNano())
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		buf := make([]byte, 65535)
		for {
			src.SetReadDeadline(time.Now().Add(idle))
			n, err := src.Read(buf)
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() && time.Since(time.Unix(0, last.Load())) < idle {
					continue // the other direction is still busy
				}
				break
			}
			last.Store(time.Now().UnixNano())
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
	var pending sync.Map // IDs of queries that wait for an answer (dnslist.go)
	go func() {          // answers back to the app
		buf := make([]byte, 65535)
		for {
			out.SetReadDeadline(time.Now().Add(dnsIdle))
			n, err := out.Read(buf)
			if err != nil {
				break
			}
			if n >= 2 {
				pending.Delete(binary.BigEndian.Uint16(buf))
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
			if list := e.blockedName(f.app, q.Question[0].Name); list != "" {
				e.dnsBlocked.Add(1)
				r := new(dns.Msg)
				r.SetRcode(&q, dns.RcodeNameError)
				if b, err := r.Pack(); err == nil {
					in.Write(b)
				}
				continue
			}
			if r := e.domainRule(f.app, q.Question[0].Name); r != nil {
				go e.resolveForRule(f, r, append([]byte(nil), buf[:n]...), in)
				continue
			}
		}
		if _, err := out.Write(buf[:n]); err != nil {
			break
		}
		e.touch(f.route)
		if f.dnsTried.IsValid() && f.route != RouteBlock && len(e.dnsServers(f.route)) > 1 {
			e.watchDNS(f, append([]byte(nil), buf[:n]...), f.dnsTried, in, &pending)
		}
	}
	in.Close()
	out.Close()
	<-done
}

// resolveForRule sends one query for a domain rule's name over the rule's
// route, remembers the addresses for the rule and answers the app. A route
// that cannot be reached answers SERVFAIL: the name must not leak out on
// the app's own route.
func (e *Engine) resolveForRule(f *flow, r *rule, query []byte, in net.Conn) {
	var q dns.Msg
	q.Unpack(query)
	fail := func(rcode int) {
		m := new(dns.Msg)
		m.SetRcode(&q, rcode)
		if b, err := m.Pack(); err == nil {
			in.Write(b)
		}
	}
	rf := &flow{proto: 17, src: f.src, dst: f.dst, app: f.app, pinned: f.pinned, route: e.ov.Route(r.route, time.Now())}
	ctx, cancel := context.WithTimeout(context.Background(), dialTimout)
	out, err := e.dial(ctx, rf)
	cancel()
	if err != nil {
		if errors.Is(err, errBlocked) {
			fail(dns.RcodeRefused)
			return
		}
		fail(dns.RcodeServerFailure)
		return
	}
	defer out.Close()
	out.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := out.Write(query); err != nil {
		fail(dns.RcodeServerFailure)
		return
	}
	buf := make([]byte, 65535)
	for {
		n, err := out.Read(buf)
		if err != nil {
			fail(dns.RcodeServerFailure)
			return
		}
		var resp dns.Msg
		if resp.Unpack(buf[:n]) != nil || resp.Id != q.Id {
			continue
		}
		e.domains.add(r.key, &resp, time.Now())
		in.Write(buf[:n])
		return
	}
}

// refuseDNS answers every query on a DNS flow that may not go anywhere
// (route block, tunnel down) with REFUSED until the flow is idle.
func refuseDNS(in net.Conn) {
	buf := make([]byte, 65535)
	for {
		in.SetReadDeadline(time.Now().Add(dnsIdle))
		n, err := in.Read(buf)
		if err != nil {
			return
		}
		var q dns.Msg
		if q.Unpack(buf[:n]) != nil || q.Response {
			continue
		}
		r := new(dns.Msg)
		r.SetRcode(&q, dns.RcodeRefused)
		if b, err := r.Pack(); err == nil {
			in.Write(b)
		}
	}
}
