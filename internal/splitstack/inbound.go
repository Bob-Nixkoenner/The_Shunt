package splitstack

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Inbound: connections that arrive through a tunnel are normally refused,
// because the tunnel address lives only in the tunnel's own userspace network
// and nothing listens there. A tunnel can name ports ("tcp/1716", "udp/1716")
// that are accepted there and handed on to the same port on the device's
// loopback, where the app listens. Optionally only from some source addresses.

const (
	inboundMaxPerSource = 16               // simultaneous TCP connections per source
	inboundUDPIdle      = 60 * time.Second // a UDP session ends after this much silence
)

type inboundPort struct {
	tcp  bool
	port uint16
}

func parseInboundPorts(list []string) ([]inboundPort, error) {
	var out []inboundPort
	for _, s := range list {
		proto, p, ok := strings.Cut(strings.ToLower(strings.TrimSpace(s)), "/")
		n, err := strconv.Atoi(p)
		if !ok || (proto != "tcp" && proto != "udp") || err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("inbound %q: use tcp/PORT or udp/PORT", s)
		}
		out = append(out, inboundPort{proto == "tcp", uint16(n)})
	}
	return out, nil
}

func parseInboundFrom(list []string) (map[netip.Addr]bool, error) {
	if len(list) == 0 {
		return nil, nil
	}
	m := map[netip.Addr]bool{}
	for _, s := range list {
		a, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil {
			return nil, fmt.Errorf("inbound_from %q: not an address", s)
		}
		m[a.Unmap()] = true
	}
	return m, nil
}

// inboundHost is where accepted connections go; a variable for tests.
var inboundHost = "127.0.0.1"

// startInbound opens the listeners in the tunnel's network. It returns a
// stop function, nil if nothing is configured or the tunnel has no network.
func (e *Engine) startInbound(t *wgTunnel, tc tunnelConf) func() {
	if len(tc.Inbound) == 0 {
		return nil
	}
	ports, err := parseInboundPorts(tc.Inbound)
	if err != nil {
		e.logf("tunnel %s: %v", tc.Name, err)
		return nil
	}
	from, err := parseInboundFrom(tc.InboundFrom)
	if err != nil {
		e.logf("tunnel %s: %v", tc.Name, err)
		return nil
	}
	n := t.netw()
	if n == nil {
		return nil
	}
	addrs := tunnelAddrs(t)
	if len(addrs) == 0 {
		e.logf("tunnel %s: inbound: no tunnel address known", tc.Name)
		return nil
	}
	var closers []func()
	for _, p := range ports {
		for _, a := range addrs { // the netstack does not take a wildcard: one listener per address
			ap := netip.AddrPortFrom(a, p.port)
			if p.tcp {
				l, err := n.ListenTCPAddrPort(ap)
				if err != nil {
					e.logf("tunnel %s: inbound tcp/%d: %v", tc.Name, p.port, err)
					continue
				}
				closers = append(closers, func() { l.Close() })
				go e.inboundTCP(tc.Name, l, p.port, from)
			} else {
				c, err := n.ListenUDPAddrPort(ap)
				if err != nil {
					e.logf("tunnel %s: inbound udp/%d: %v", tc.Name, p.port, err)
					continue
				}
				closers = append(closers, func() { c.Close() })
				go e.inboundUDP(tc.Name, c, p.port, from)
			}
			e.logf("tunnel %s: inbound %s/%d open on %s", tc.Name, map[bool]string{true: "tcp", false: "udp"}[p.tcp], p.port, a)
		}
	}
	return func() {
		for _, c := range closers {
			c()
		}
	}
}

// tunnelAddrs: the addresses of this device inside the tunnel.
func tunnelAddrs(t *wgTunnel) []netip.Addr {
	var out []netip.Addr
	if t.isOVPN() {
		if ot := t.ovpnTunnel(); ot != nil {
			out = append(out, ot.Addrs()...)
		}
	} else if t.conf != nil {
		for _, p := range t.conf.Addresses {
			out = append(out, p.Addr())
		}
	}
	return out
}

func srcAddr(a net.Addr) (netip.Addr, bool) {
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.Addr{}, false
	}
	return ap.Addr().Unmap(), true
}

func (e *Engine) inboundTCP(name string, l net.Listener, port uint16, from map[netip.Addr]bool) {
	var mu sync.Mutex
	active := map[netip.Addr]int{}
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		src, ok := srcAddr(c.RemoteAddr())
		if !ok || (from != nil && !from[src]) {
			c.Close()
			continue
		}
		mu.Lock()
		if active[src] >= inboundMaxPerSource {
			mu.Unlock()
			c.Close()
			continue
		}
		active[src]++
		mu.Unlock()
		go func() {
			defer func() { mu.Lock(); active[src]--; mu.Unlock() }()
			d := net.Dialer{Timeout: 5 * time.Second}
			out, err := d.DialContext(context.Background(), "tcp", net.JoinHostPort(inboundHost, strconv.Itoa(int(port))))
			if err != nil {
				c.Close()
				return
			}
			relayTCP(c, out)
		}()
	}
}

func (e *Engine) inboundUDP(name string, c net.PacketConn, port uint16, from map[netip.Addr]bool) {
	type sess struct {
		out  net.Conn
		last time.Time
	}
	var mu sync.Mutex
	sessions := map[string]*sess{}
	go func() { // end quiet sessions
		for range time.Tick(inboundUDPIdle / 4) {
			mu.Lock()
			for k, s := range sessions {
				if time.Since(s.last) > inboundUDPIdle {
					s.out.Close()
					delete(sessions, k)
				}
			}
			mu.Unlock()
		}
	}()
	buf := make([]byte, 65535)
	for {
		nr, raddr, err := c.ReadFrom(buf)
		if err != nil {
			mu.Lock()
			for _, s := range sessions {
				s.out.Close()
			}
			mu.Unlock()
			return
		}
		src, ok := srcAddr(raddr)
		if !ok || (from != nil && !from[src]) {
			continue
		}
		key := raddr.String()
		mu.Lock()
		s := sessions[key]
		if s == nil {
			out, err := net.Dial("udp", net.JoinHostPort(inboundHost, strconv.Itoa(int(port))))
			if err != nil {
				mu.Unlock()
				continue
			}
			s = &sess{out: out}
			sessions[key] = s
			go func(out net.Conn, back net.Addr) { // answers back to the sender
				b := make([]byte, 65535)
				for {
					m, err := out.Read(b)
					if err != nil {
						return
					}
					mu.Lock()
					if x := sessions[key]; x != nil {
						x.last = time.Now()
					}
					mu.Unlock()
					c.WriteTo(b[:m], back)
				}
			}(out, raddr)
		}
		s.last = time.Now()
		out := s.out
		mu.Unlock()
		out.Write(buf[:nr])
	}
}
