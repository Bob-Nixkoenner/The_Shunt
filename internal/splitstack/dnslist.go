package splitstack

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/health"
	"github.com/miekg/dns"
)

// DNS servers per route. A route asks, in this order: its own server (the
// DNS of the tunnel's file, the pushed one of OpenVPN, Tailscale's resolver;
// for direct the one from the settings), then the extra servers of the
// config ("dns_servers": public ones such as 1.1.1.1, 8.8.8.8, or the
// user's own). With "ignore_tunnel_dns" the tunnel's own is left out
// (Tailscale's resolver stays: MagicDNS names exist nowhere else).
//
// A query nobody answers within dnsRetryAfter goes to the next server; the
// one that answered is asked first for dnsGoodFor.

var (
	dnsRetryAfter = 2 * time.Second
	dnsGoodFor    = 5 * time.Minute
)

const maxDNSServers = 8

type dnsGood struct {
	addr netip.Addr
	at   time.Time
}

// dnsGoods remembers the last server that answered, per route.
type dnsGoods struct{ m sync.Map }

func (g *dnsGoods) get(route string) (netip.Addr, bool) {
	v, ok := g.m.Load(route)
	if !ok {
		return netip.Addr{}, false
	}
	d := v.(dnsGood)
	return d.addr, time.Since(d.at) < dnsGoodFor
}

func (g *dnsGoods) set(route string, a netip.Addr) { g.m.Store(route, dnsGood{a, time.Now()}) }

// dnsList is the DNS servers a tunnel brings along.
func (t *wgTunnel) dnsList() []netip.Addr {
	if t.isTS() || t.isOVPN() {
		return []netip.Addr{t.dnsAddr()}
	}
	if len(t.dnsAll) > 0 {
		return t.dnsAll
	}
	return []netip.Addr{t.dns}
}

// dnsServers is the list a route asks, in order.
func (e *Engine) dnsServers(route string) []netip.Addr {
	e.mu.RLock()
	extra, ignore := e.dnsExtra, e.ignoreTunnelDNS
	e.mu.RUnlock()
	var list []netip.Addr
	add := func(a netip.Addr) {
		if a.IsValid() && !slices.Contains(list, a) {
			list = append(list, a)
		}
	}
	var t *wgTunnel
	if route == RouteDirect {
		add(e.directDNS())
	} else if name, ok := strings.CutPrefix(route, tunnelPref); ok {
		t = e.tunnel(name)
		if t != nil && (!ignore || t.isTS()) {
			for _, a := range t.dnsList() {
				add(a)
			}
		}
	}
	for _, a := range extra {
		add(a)
	}
	if t != nil && !t.dormant { // a server of a family the tunnel lacks cannot be reached
		v4, v6 := t.families()
		list = slices.DeleteFunc(list, func(a netip.Addr) bool { return (a.Is4() && !v4) || (a.Is6() && !v6) })
	}
	if len(list) == 0 {
		list = []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	}
	if g, ok := e.dnsGood.get(route); ok {
		if i := slices.Index(list, g); i > 0 {
			list = slices.Insert(slices.Delete(list, i, i+1), 0, g)
		}
	}
	return list
}

// probeDNS asks the servers of a tunnel one after the other until one answers.
func (e *Engine) probeDNS(ctx context.Context, t *wgTunnel) (rtt time.Duration, err error) {
	for _, s := range e.dnsServers(tunnelPref + t.name) {
		pctx, cancel := context.WithTimeout(ctx, dnsRetryAfter)
		rtt, err = health.DNSProbe(pctx, t.dialUDP, s)
		cancel()
		if err == nil {
			e.dnsGood.set(tunnelPref+t.name, s)
			return rtt, nil
		}
	}
	return 0, err
}

// watchDNS gives a query sent to the first server a second chance: if no
// answer comes within dnsRetryAfter, the other servers are asked in turn.
// pending holds the IDs of queries without an answer yet (relayDNS deletes
// an ID when the answer arrives).
func (e *Engine) watchDNS(f *flow, query []byte, tried netip.Addr, in net.Conn, pending *sync.Map) {
	var q dns.Msg
	if q.Unpack(query) != nil {
		return
	}
	pending.Store(q.Id, true)
	time.AfterFunc(dnsRetryAfter, func() {
		if _, ok := pending.Load(q.Id); !ok {
			return
		}
		for _, s := range e.dnsServers(f.route) {
			if s == tried {
				continue
			}
			if e.askDNS(f, s, query, q.Id, in, pending) {
				e.dnsGood.set(f.route, s)
				e.logf("dns: %s did not answer, %s did (%s)", tried, s, f.route)
				return
			}
			if _, ok := pending.Load(q.Id); !ok {
				return // answered meanwhile by the first server
			}
		}
		if _, ok := pending.LoadAndDelete(q.Id); ok {
			m := new(dns.Msg)
			m.SetRcode(&q, dns.RcodeServerFailure)
			if b, err := m.Pack(); err == nil {
				in.Write(b)
			}
		}
	})
}

// askDNS sends one query to server s on the route of f and gives the answer
// to the app; false if s did not answer in time.
func (e *Engine) askDNS(f *flow, s netip.Addr, query []byte, id uint16, in net.Conn, pending *sync.Map) bool {
	ctx, cancel := context.WithTimeout(context.Background(), dnsRetryAfter)
	defer cancel()
	out, err := e.dialTo(ctx, f, netip.AddrPortFrom(s, 53))
	if err != nil {
		return false
	}
	defer out.Close()
	out.SetDeadline(time.Now().Add(dnsRetryAfter))
	if _, err := out.Write(query); err != nil {
		return false
	}
	buf := make([]byte, 65535)
	for {
		n, err := out.Read(buf)
		if err != nil {
			return false
		}
		var r dns.Msg
		if r.Unpack(buf[:n]) != nil || r.Id != id {
			continue
		}
		if _, ok := pending.LoadAndDelete(id); ok {
			in.Write(buf[:n])
		}
		return true
	}
}
