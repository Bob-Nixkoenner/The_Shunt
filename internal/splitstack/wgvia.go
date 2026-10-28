package splitstack

import (
	"errors"
	"net"
	"net/netip"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

// Multi-hop for WireGuard (tunnelConf.Via): the inner tunnel's UDP socket
// lives in the carrier tunnel's netstack, so its encrypted packets leave
// inside the carrier (second hop: the carrier's server sees only the inner
// tunnel's server, which sees only the carrier's exit).

// wgViaOverhead: the inner tunnel's packets must fit into the carrier's
// (IPv6 40 + UDP 8 + WireGuard 32).
const wgViaOverhead = 80

// tunnelBind is a conn.Bind on a carrier tunnel's netstack.
type tunnelBind struct {
	carrier *netstack.Net
	// the carrier's own addresses (invalid = none of that family); gVisor
	// finds no route for a socket on 0.0.0.0
	v4, v6 netip.Addr

	mu     sync.Mutex
	c4, c6 *gonet.UDPConn
}

func (b *tunnelBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.c4 != nil || b.c6 != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	var fns []conn.ReceiveFunc
	open := func(local netip.Addr) (*gonet.UDPConn, error) {
		c, err := b.carrier.ListenUDPAddrPort(netip.AddrPortFrom(local, port))
		if err != nil {
			return nil, err
		}
		if port == 0 { // the same port for the other family
			if ua, ok := c.LocalAddr().(*net.UDPAddr); ok {
				port = uint16(ua.Port)
			}
		}
		fns = append(fns, func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
			n, a, err := c.ReadFrom(bufs[0])
			if err != nil {
				return 0, err
			}
			ua, _ := a.(*net.UDPAddr)
			if ua == nil {
				return 0, errors.New("via: not a UDP address")
			}
			sizes[0], eps[0] = n, &conn.StdNetEndpoint{AddrPort: ua.AddrPort()}
			return 1, nil
		})
		return c, nil
	}
	var err error
	if b.v4.IsValid() {
		if b.c4, err = open(b.v4); err != nil {
			return nil, 0, err
		}
	}
	if b.v6.IsValid() {
		if b.c6, err = open(b.v6); err != nil {
			b.closeLocked()
			return nil, 0, err
		}
	}
	if len(fns) == 0 {
		return nil, 0, errors.New("via: the carrier tunnel has no address")
	}
	return fns, port, nil
}

func (b *tunnelBind) closeLocked() {
	for _, c := range []*gonet.UDPConn{b.c4, b.c6} {
		if c != nil {
			c.Close()
		}
	}
	b.c4, b.c6 = nil, nil
}

func (b *tunnelBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closeLocked()
	return nil
}

func (b *tunnelBind) SetMark(uint32) error { return nil }
func (b *tunnelBind) BatchSize() int       { return 1 }

func (b *tunnelBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	return &conn.StdNetEndpoint{AddrPort: ap}, err
}

func (b *tunnelBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	se, ok := ep.(*conn.StdNetEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	b.mu.Lock()
	c := b.c4
	if se.Addr().Unmap().Is6() {
		c = b.c6
	}
	b.mu.Unlock()
	if c == nil {
		return errors.New("via: the carrier tunnel cannot reach " + se.Addr().String())
	}
	to := net.UDPAddrFromAddrPort(netip.AddrPortFrom(se.Addr().Unmap(), se.Port()))
	for _, p := range bufs {
		if _, err := c.WriteTo(p, to); err != nil {
			return err
		}
	}
	return nil
}

// newWGVia starts WireGuard tunnel t inside its carrier t.Via (a WireGuard
// tunnel that is up; carriers start first and never sleep, see onDemandEligible).
func (e *Engine) newWGVia(t tunnelConf, mtu int) (*wgTunnel, error) {
	outer := e.tunnel(t.Via)
	if outer == nil || outer.isOVPN() || outer.tsType || outer.torType {
		return nil, errors.New("via: " + t.Via + " is not a WireGuard tunnel here")
	}
	if outer.net == nil {
		return nil, errors.New("via: tunnel " + t.Via + " is not up")
	}
	b := &tunnelBind{carrier: outer.net}
	if outer.conf != nil {
		for _, a := range outer.conf.Addresses {
			if a.Addr().Is4() && !b.v4.IsValid() {
				b.v4 = a.Addr()
			} else if a.Addr().Is6() && !b.v6.IsValid() {
				b.v6 = a.Addr()
			}
		}
	}
	wt, err := newWGTunnel(t.Name, t.Conf, e.resolver(), b, nil, mtu-wgViaOverhead)
	if wt != nil {
		wt.viaName = t.Via
	}
	return wt, err
}
