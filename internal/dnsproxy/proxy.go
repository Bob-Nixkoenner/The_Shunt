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
	"maps"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/Bob-Nixkoenner/the_shunt/internal/doh"

	"github.com/Bob-Nixkoenner/the_shunt/internal/blocklist"
	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/Bob-Nixkoenner/the_shunt/internal/engine"
)

// CaptiveUpstreams is the RouteUpstreams key of the Wi-Fi login browser.
const CaptiveUpstreams = "captive"

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
	// setDomains: the domains each set was filled for (set name -> list)
	setDomains map[string]string

	healthMu sync.Mutex
	health   map[string]*routeHealth

	filter  atomic.Pointer[blocklist.Filter]
	statsMu sync.Mutex
	stats   FilterStats

	// Owner names the program that sent a query ("tcp"/"udp", its source
	// address); asked only for blocked queries. nil = not counted per app.
	Owner func(proto string, from netip.AddrPort) string
}

// FilterStats counts what the DNS filter blocked since the daemon started.
type FilterStats struct {
	Blocked uint64            `json:"blocked"`
	ByLevel map[string]uint64 `json:"by_level,omitempty"`
	// ByApp: blocked queries per program (see Proxy.Owner), "" = unknown.
	ByApp map[string]uint64 `json:"by_app,omitempty"`
	// Recent: the last blocked queries, newest first.
	Recent []Blocked `json:"recent,omitempty"`
}

// Blocked is one blocked query.
type Blocked struct {
	Time  time.Time `json:"time"`
	Name  string    `json:"name"`
	Level string    `json:"level"`
	List  string    `json:"list"`
	Route string    `json:"route"`
	App   string    `json:"app,omitempty"`
}

// RecentBlocked: how many blocked queries FilterStats keeps.
const RecentBlocked = 50

// maxApps bounds FilterStats.ByApp (short-lived programs come and go).
const maxApps = 500

// SetFilter switches to a new blocklist snapshot (nil = nothing blocked).
func (p *Proxy) SetFilter(f *blocklist.Filter) { p.filter.Store(f) }

// FilterStats returns a copy of the counters.
func (p *Proxy) FilterStats() FilterStats {
	p.statsMu.Lock()
	defer p.statsMu.Unlock()
	s := FilterStats{Blocked: p.stats.Blocked, ByLevel: maps.Clone(p.stats.ByLevel), ByApp: maps.Clone(p.stats.ByApp), Recent: slices.Clone(p.stats.Recent)}
	if s.ByLevel == nil {
		s.ByLevel = map[string]uint64{}
	}
	return s
}

func (p *Proxy) countBlocked(b Blocked) {
	p.statsMu.Lock()
	defer p.statsMu.Unlock()
	if p.stats.ByLevel == nil {
		p.stats.ByLevel = map[string]uint64{}
	}
	p.stats.Blocked++
	p.stats.ByLevel[b.Level]++
	if p.Owner != nil {
		if p.stats.ByApp == nil {
			p.stats.ByApp = map[string]uint64{}
		}
		if _, ok := p.stats.ByApp[b.App]; ok || len(p.stats.ByApp) < maxApps {
			p.stats.ByApp[b.App]++
		}
	}
	if n := len(p.stats.Recent); n > 0 && p.stats.Recent[0].Name == b.Name && p.stats.Recent[0].Level == b.Level && p.stats.Recent[0].App == b.App {
		p.stats.Recent[0].Time = b.Time // a retrying program fills nothing up
		return
	}
	p.stats.Recent = append([]Blocked{b}, p.stats.Recent...)
	if len(p.stats.Recent) > RecentBlocked {
		p.stats.Recent = p.stats.Recent[:RecentBlocked]
	}
}

// routeHealth follows whether a route's upstreams answer. Failures are
// logged when the state changes, not per query: a DNS server that is not
// reachable through its route (a LAN Pi-hole behind a tunnel) would
// otherwise flood the log and nobody would notice.
type routeHealth struct {
	fails    int // consecutive queries without any upstream answering
	since    time.Time
	lastErr  string
	reported bool
}

// FailAfter: a route counts as failing after this many consecutive failed
// queries spread over at least FailFor (a tunnel that is still connecting
// is not reported).
const (
	FailAfter = 3
	FailFor   = 15 * time.Second
)

// Health returns the routes whose DNS is failing, with the last error.
func (p *Proxy) Health() map[string]string {
	p.healthMu.Lock()
	defer p.healthMu.Unlock()
	out := map[string]string{}
	for r, h := range p.health {
		if h.reported {
			out[r] = h.lastErr
		}
	}
	return out
}

func (p *Proxy) record(route string, err error) {
	p.healthMu.Lock()
	defer p.healthMu.Unlock()
	if p.health == nil {
		p.health = map[string]*routeHealth{}
	}
	h := p.health[route]
	if h == nil {
		h = &routeHealth{}
		p.health[route] = h
	}
	if err == nil {
		if h.reported {
			p.Log.Info("dns works again", "route", route)
		}
		*h = routeHealth{}
		return
	}
	if h.fails == 0 {
		h.since = time.Now()
	}
	h.fails++
	h.lastErr = err.Error()
	if !h.reported && h.fails >= FailAfter && time.Since(h.since) >= FailFor {
		h.reported = true
		p.Log.Warn("dns failing: no upstream of this route answers", "route", route, "err", err)
	}
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
		if plan.Captive != nil {
			byPort[plan.Captive.DNSPort] = plan.Captive
		}
		for _, r := range plan.FilterRoutes {
			byPort[r.DNSPort] = r
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

	// Set names follow the rule's position in the file: after an edit the
	// same name may belong to a rule with other domains, whose addresses
	// must not inherit the old ones.
	keep := map[string]bool{}
	domains := map[string]string{}
	for _, r := range plan.DomainRules() {
		ds := strings.Join(r.Domains, ",")
		for _, set := range []string{r.SetV4, r.SetV6} {
			domains[set] = ds
			keep[set] = p.setDomains[set] == "" || p.setDomains[set] == ds
		}
	}
	p.setDomains = domains
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
			var s *dns.Server
			marked := false
			if netw == "udp" {
				s = newUDPServer(a, h, func() { started <- nil })
				marked = s != nil
			}
			if s == nil {
				s = &dns.Server{Addr: a, Net: netw, Handler: h, NotifyStartedFunc: func() { started <- nil }}
			}
			go func() {
				var err error
				if marked {
					err = s.ActivateAndServe()
				} else {
					err = s.ListenAndServe()
				}
				if err != nil {
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
	who := func() string {
		if p.Owner == nil {
			return ""
		}
		proto := "udp"
		if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
			proto = "tcp"
		}
		from, err := netip.ParseAddrPort(w.RemoteAddr().String())
		if err != nil {
			return ""
		}
		return p.Owner(proto, from)
	}
	resp := p.handle(port, r, queryMark(w), who)
	resp.Id = r.Id
	if err := w.WriteMsg(resp); err != nil {
		p.Log.Debug("dns write", "err", err)
	}
}

// who names the sender (nil = unknown); called only when the filter blocks.
func (p *Proxy) handle(port int, r *dns.Msg, mark uint32, who func() string) *dns.Msg {
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
	// the query is answered for the route its packet was marked for, not the
	// one the (per conntrack entry) redirect happened to choose
	if mark != markUnknown {
		if own := routeOfMark(plan, mark); own == nil {
			if mark == engine.MarkBlock {
				return fail(r, dns.RcodeNameError)
			}
		} else if own.Mark != src.Mark {
			p.Log.Debug("dns query came to the wrong listener, answering for its own route", "listener", src.String(), "route", own.String())
			src = own
		}
	}
	if doh.Unwanted(name, plan.BlockDoH) {
		return fail(r, dns.RcodeNameError)
	}

	route := src
	var rule *engine.Rule
	for _, dr := range plan.DomainRules() {
		if src.Captive {
			break // the login browser asks the network, nothing else
		}
		if matchDomain(name, dr.Domains) {
			rule, route = dr, dr.Route
			break
		}
	}
	if route.Kind == config.RouteBlock {
		return fail(r, dns.RcodeNameError)
	}
	// The blocklists: not for the login browser (portals live on odd
	// names), not for names you routed on purpose with a domain rule.
	if rule == nil && !src.Captive && src.Filter != "" && src.Filter != config.FilterOff {
		if list := p.filter.Load().Check(src.Filter, name); list != "" {
			b := Blocked{Time: time.Now(), Name: name, Level: src.Filter, List: list, Route: src.String()}
			if who != nil {
				b.App = who()
			}
			p.countBlocked(b)
			return fail(r, dns.RcodeNameError)
		}
	}

	q2 := r.Copy()
	stripECS(q2)
	ctx, cancel := context.WithTimeout(context.Background(), 2*upstreamTimeout)
	defer cancel()
	var resp *dns.Msg
	lastErr := fmt.Errorf("no DNS server configured for this route")
	key := route.String()
	if route.Captive {
		key = CaptiveUpstreams
	}
	for _, u := range ups[key] {
		resp, lastErr = u.Exchange(ctx, q2)
		if lastErr == nil {
			break
		}
		lastErr = fmt.Errorf("%s: %w", u.String(), lastErr)
		p.Log.Debug("dns upstream failed", "route", route.String(), "err", lastErr)
	}
	p.record(key, lastErr)
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

// routeOfMark finds the route a packet mark stands for (no mark: direct).
func routeOfMark(plan *engine.Plan, mark uint32) *engine.Route {
	if mark&engine.MarkMask != engine.MarkBase {
		mark = engine.MarkDirect
	}
	for _, r := range plan.Routes {
		if r.Kind != config.RouteBlock && r.Mark == mark {
			return r
		}
	}
	if plan.Captive != nil && plan.Captive.Mark == mark {
		return plan.Captive
	}
	return nil
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
