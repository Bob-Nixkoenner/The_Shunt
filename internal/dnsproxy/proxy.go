// Package dnsproxy is Shunt's per-route DNS forwarder.
//
// nftables redirects every DNS query (port 53) to the listener of the route
// the asking process belongs to. The proxy then picks the upstream:
//
//   - the name matches a domain rule → that rule's route and its upstream,
//     and the answer's addresses go into the rule's nftables sets *before*
//     the answer is returned (otherwise the first connection races the set);
//   - otherwise → the upstream of the route the query came from.
//
// Upstream queries leave with the route's packet mark, so "what goes
// through a tunnel is resolved through that tunnel" holds by construction.
package dnsproxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/Bob-Nixkoenner/the_shunt/internal/engine"
)

// RouteUpstreams maps a route (by name, e.g. "tunnel:vps") to its upstreams,
// tried in order.
type RouteUpstreams map[string][]Upstream

// Proxy serves all route listeners.
type Proxy struct {
	Log *slog.Logger

	sets *pairSets

	mu        sync.RWMutex
	plan      *engine.Plan
	upstreams RouteUpstreams
	byPort    map[int]*engine.Route
	servers   map[int][]*dns.Server
}

// New creates a proxy writing domain-rule addresses through w.
func New(log *slog.Logger, w SetWriter) *Proxy {
	return &Proxy{Log: log, sets: newPairSets(w), servers: map[int][]*dns.Server{}}
}

// Update switches to a new plan: listeners are added/removed as needed and
// remembered domain-rule addresses are written into the (new) sets. Call it
// right after the plan's ruleset was applied.
func (p *Proxy) Update(plan *engine.Plan, ups RouteUpstreams) error {
	byPort := map[int]*engine.Route{}
	if plan.DNS {
		for _, r := range plan.Routes {
			if r.Kind != config.RouteBlock {
				byPort[r.DNSPort] = r
			}
		}
	}
	p.mu.Lock()
	p.plan, p.upstreams, p.byPort = plan, ups, byPort
	p.mu.Unlock()

	for port, srvs := range p.servers {
		if _, ok := byPort[port]; !ok {
			for _, s := range srvs {
				_ = s.Shutdown()
			}
			delete(p.servers, port)
		}
	}
	for port := range byPort {
		if _, ok := p.servers[port]; ok {
			continue
		}
		srvs, err := p.listen(port)
		if err != nil {
			return err
		}
		p.servers[port] = srvs
	}

	keep := map[string]bool{}
	for _, r := range plan.DomainRules() {
		keep[r.SetV4] = true
		keep[r.SetV6] = true
	}
	return p.sets.replay(keep)
}

// Close stops all listeners.
func (p *Proxy) Close() {
	for _, srvs := range p.servers {
		for _, s := range srvs {
			_ = s.Shutdown()
		}
	}
	p.servers = map[int][]*dns.Server{}
}

func (p *Proxy) listen(port int) ([]*dns.Server, error) {
	addrs := []string{net.JoinHostPort("127.0.0.1", strconv.Itoa(port))}
	if _, err := os.Stat("/proc/sys/net/ipv6"); err == nil {
		addrs = append(addrs, net.JoinHostPort("::1", strconv.Itoa(port)))
	}
	h := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) { p.serve(port, w, r) })
	var out []*dns.Server
	for _, a := range addrs {
		for _, netw := range []string{"udp", "tcp"} {
			started := make(chan error, 1)
			s := &dns.Server{Addr: a, Net: netw, Handler: h, NotifyStartedFunc: func() { started <- nil }}
			go func() {
				if err := s.ListenAndServe(); err != nil {
					select {
					case started <- err:
					default:
						p.Log.Error("dns listener stopped", "addr", a, "net", netw, "err", err)
					}
				}
			}()
			if err := <-started; err != nil {
				for _, o := range out {
					_ = o.Shutdown()
				}
				return nil, fmt.Errorf("dns listen %s/%s: %w", a, netw, err)
			}
			out = append(out, s)
		}
	}
	return out, nil
}

func (p *Proxy) serve(port int, w dns.ResponseWriter, r *dns.Msg) {
	// Answers come from upstreams we don't control: a bug triggered by a
	// crafted answer must cost one query, not the daemon.
	defer func() {
		if e := recover(); e != nil {
			p.Log.Error("dns handler panic", "err", e)
			m := fail(r, dns.RcodeServerFailure)
			_ = w.WriteMsg(m)
		}
	}()
	resp := p.handle(port, r)
	resp.Id = r.Id
	if err := w.WriteMsg(resp); err != nil {
		p.Log.Debug("dns write", "err", err)
	}
}

func (p *Proxy) handle(port int, r *dns.Msg) *dns.Msg {
	if len(r.Question) != 1 {
		return fail(r, dns.RcodeFormatError)
	}
	q := r.Question[0]
	name := strings.TrimSuffix(strings.ToLower(q.Name), ".")

	p.mu.RLock()
	plan, ups, src := p.plan, p.upstreams, p.byPort[port]
	p.mu.RUnlock()
	if src == nil {
		return fail(r, dns.RcodeServerFailure)
	}
	if name == canaryDomain || (plan.BlockDoH && isDoHHost(name)) {
		return fail(r, dns.RcodeNameError)
	}

	route := src
	var rule *engine.Rule
	for _, dr := range plan.DomainRules() {
		if matchDomain(name, dr.Domains) {
			rule, route = dr, dr.Route
			break
		}
	}
	if route.Kind == config.RouteBlock {
		return fail(r, dns.RcodeNameError)
	}

	q2 := r.Copy()
	stripECS(q2)
	ctx, cancel := context.WithTimeout(context.Background(), 2*upstreamTimeout)
	defer cancel()
	var resp *dns.Msg
	var lastErr error
	for _, u := range ups[route.String()] {
		resp, lastErr = u.Exchange(ctx, q2)
		if lastErr == nil {
			break
		}
		p.Log.Warn("dns upstream failed", "route", route.String(), "upstream", u.String(), "err", lastErr)
	}
	if resp == nil {
		// No fallback to another route: failing is the safe outcome.
		return fail(r, dns.RcodeServerFailure)
	}
	if rule != nil {
		if err := p.recordAnswer(rule, resp); err != nil {
			p.Log.Error("cannot add addresses to domain set, refusing answer", "rule", rule.Name, "err", err)
			return fail(r, dns.RcodeServerFailure)
		}
	}
	return resp
}

// recordAnswer puts the answer's addresses into the rule's sets and caps
// the TTLs so clients never cache longer than the set entries live.
func (p *Proxy) recordAnswer(rule *engine.Rule, resp *dns.Msg) error {
	var v4, v6 []netip.Addr
	ttl := uint32(1<<31 - 1)
	for _, rr := range resp.Answer {
		switch a := rr.(type) {
		case *dns.A:
			if ip, ok := netip.AddrFromSlice(a.A.To4()); ok && Routable(ip) {
				v4 = append(v4, ip)
			}
		case *dns.AAAA:
			if ip, ok := netip.AddrFromSlice(a.AAAA); ok && Routable(ip) {
				v6 = append(v6, ip)
			}
		default:
			continue
		}
		ttl = min(ttl, rr.Header().Ttl)
	}
	if len(v4)+len(v6) == 0 {
		return nil
	}
	d := time.Duration(ttl) * time.Second
	safe := d
	if len(v4) > 0 {
		s, err := p.sets.ensure(rule.SetV4, v4, d)
		if err != nil {
			return err
		}
		safe = min(safe, s)
	}
	if len(v6) > 0 {
		s, err := p.sets.ensure(rule.SetV6, v6, d)
		if err != nil {
			return err
		}
		safe = min(safe, s)
	}
	capTTL := uint32(safe / time.Second)
	for _, rr := range resp.Answer {
		if rr.Header().Ttl > capTTL {
			rr.Header().Ttl = capTTL
		}
	}
	return nil
}

// Routable reports whether a DNS answer address may go into a domain set.
// Blocking answers (0.0.0.0, ::, as Pi-hole and AdGuard give them),
// loopback, link-local, multicast and broadcast never steer routing.
// Private ranges stay allowed: domain rules for LAN services are legitimate.
func Routable(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.IsValid() && !ip.IsUnspecified() && !ip.IsLoopback() && !ip.IsMulticast() &&
		!ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() && !ip.IsInterfaceLocalMulticast() &&
		ip != netip.AddrFrom4([4]byte{255, 255, 255, 255}) &&
		!netip.MustParsePrefix("0.0.0.0/8").Contains(ip)
}

func fail(r *dns.Msg, rcode int) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(r, rcode)
	m.RecursionAvailable = true
	return m
}

func matchDomain(name string, domains []string) bool {
	for _, d := range domains {
		if name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
}

// stripECS removes EDNS Client Subnet: upstreams don't need to know the
// client's network.
func stripECS(m *dns.Msg) {
	opt := m.IsEdns0()
	if opt == nil {
		return
	}
	kept := opt.Option[:0]
	for _, o := range opt.Option {
		if o.Option() != dns.EDNS0SUBNET {
			kept = append(kept, o)
		}
	}
	opt.Option = kept
}

// canaryDomain tells Firefox that the network does not want DoH
// (https://support.mozilla.org/kb/canary-domain-use-application-dnsnet).
const canaryDomain = "use-application-dns.net"

// Well-known public DoH endpoints. Answering NXDOMAIN for them makes
// browsers fall back to the system resolver, i.e. to us.
var dohHosts = []string{
	"dns.google", "dns.google.com", "8888.google",
	"cloudflare-dns.com", "mozilla.cloudflare-dns.com", "chrome.cloudflare-dns.com",
	"one.one.one.one", "1dot1dot1dot1.cloudflare-dns.com", "security.cloudflare-dns.com", "family.cloudflare-dns.com",
	"dns.quad9.net", "dns9.quad9.net", "dns10.quad9.net", "dns11.quad9.net", "dns12.quad9.net",
	"doh.opendns.com", "doh.familyshield.opendns.com", "dns.umbrella.com",
	"dns.nextdns.io", "doh.cleanbrowsing.org",
	"dns.adguard.com", "dns.adguard-dns.com", "dns-unfiltered.adguard.com", "dns-family.adguard.com",
	"doh.mullvad.net", "dns.mullvad.net", "adblock.dns.mullvad.net", "base.dns.mullvad.net",
	"doh.dns.sb", "dns.controld.com", "freedns.controld.com",
	"doh.libredns.gr", "doh.applied-privacy.net", "dns.digitale-gesellschaft.ch",
	"dns.switch.ch", "doh.ffmuc.net", "dns3.digitalcourage.de", "dns.alidns.com", "doh.pub",
}

func isDoHHost(name string) bool { return matchDomain(name, dohHosts) }
