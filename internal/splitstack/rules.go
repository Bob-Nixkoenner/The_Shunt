package splitstack

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	shuntcfg "github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/miekg/dns"
)

// networkConf is a network profile, the counterpart of [[network]] in
// shunt.toml: on a matching network it replaces the default route and the
// DNS server of the direct route. The platform reports the network with
// SetNetwork. Android cannot see the router's MAC, so an SSID alone decides
// (easy to fake: the UI warns when such a profile relaxes the route).
type networkConf struct {
	Name      string   `json:"name"`
	SSID      []string `json:"ssid"`       // Wi-Fi names; empty: any
	Link      string   `json:"link"`       // wifi | mobile | ethernet; "": any
	Default   string   `json:"default"`    // "": keep the config's default
	DirectDNS string   `json:"direct_dns"` // "": keep the config's direct_dns
}

// ruleConf routes by destination, the counterpart of [[rule]] with
// domain/cidr/port. Selectors of different kinds are ANDed, entries within
// one kind ORed; the first matching rule wins and beats the app rules.
type ruleConf struct {
	Name    string   `json:"name"`
	Apps    []string `json:"apps"`    // empty: every app
	Domains []string `json:"domains"` // "example.com" also matches sub.example.com
	CIDR    []string `json:"cidr"`
	Ports   []string `json:"ports"` // "tcp/22", "udp/6881-6889"
	Route   string   `json:"route"`
}

type rule struct {
	name    string
	key     string // name + position: entry in domainAddrs
	apps    map[string]bool
	domains []string
	cidr    []netip.Prefix
	ports   []shuntcfg.PortSel
	route   string
}

func compileRules(rs []ruleConf, check func(string) error) ([]rule, error) {
	var out []rule
	for i, rc := range rs {
		where := rc.Name
		if where == "" {
			where = fmt.Sprintf("#%d", i+1)
		}
		r := rule{name: rc.Name, key: fmt.Sprintf("%s\x00%d", rc.Name, i), route: rc.Route}
		if err := check(rc.Route); err != nil {
			return nil, fmt.Errorf("rule %s: %w", where, err)
		}
		if len(rc.Domains)+len(rc.CIDR)+len(rc.Ports) == 0 {
			return nil, fmt.Errorf("rule %s: needs domains, cidr or ports (app-only rules go to apps)", where)
		}
		if len(rc.Apps) > 0 {
			r.apps = map[string]bool{}
			for _, a := range rc.Apps {
				r.apps[a] = true
			}
		}
		for _, d := range rc.Domains {
			n := shuntcfg.NormalizeDomain(d)
			if n == "" {
				return nil, fmt.Errorf("rule %s: invalid domain %q", where, d)
			}
			r.domains = append(r.domains, n)
		}
		for _, c := range rc.CIDR {
			p, err := netip.ParsePrefix(c)
			if err != nil {
				a, err2 := netip.ParseAddr(c)
				if err2 != nil {
					return nil, fmt.Errorf("rule %s: %w", where, err)
				}
				p = netip.PrefixFrom(a, a.BitLen())
			}
			r.cidr = append(r.cidr, p.Masked())
		}
		for _, s := range rc.Ports {
			p, err := shuntcfg.ParsePort(s)
			if err != nil {
				return nil, fmt.Errorf("rule %s: %w", where, err)
			}
			r.ports = append(r.ports, p)
		}
		out = append(out, r)
	}
	return out, nil
}

func matchDomain(name string, domains []string) bool {
	for _, d := range domains {
		if name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
}

// matches reports whether r applies to a connection of app to dst.
// byDomain says whether dst was answered for one of r's domains.
func (r *rule) matches(app string, proto int, dst netip.AddrPort, byDomain bool) bool {
	if r.apps != nil && !appInSet(r.apps, app) {
		return false
	}
	if len(r.domains) > 0 && !byDomain {
		return false
	}
	if len(r.cidr) > 0 {
		ok := false
		for _, p := range r.cidr {
			ok = ok || p.Contains(dst.Addr().Unmap())
		}
		if !ok {
			return false
		}
	}
	if len(r.ports) > 0 {
		ok := false
		pr := map[int]string{6: "tcp", 17: "udp"}[proto]
		for _, p := range r.ports {
			ok = ok || (p.Proto == pr && dst.Port() >= p.From && dst.Port() <= p.To)
		}
		if !ok {
			return false
		}
	}
	return true
}

// domainRule returns the first rule with a domain matching a DNS name
// asked by app, or nil. Its DNS query goes over the rule's route, like on
// the desktop: the answer then fits the route the connection takes.
func (e *Engine) domainRule(app, name string) *rule {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	e.mu.RLock()
	defer e.mu.RUnlock()
	for i := range e.rules {
		r := &e.rules[i]
		if len(r.domains) == 0 || (r.apps != nil && !r.apps[app]) {
			continue
		}
		if matchDomain(name, r.domains) {
			return r
		}
	}
	return nil
}

// Addresses answered for domain rules are kept like the desktop's nftables
// sets: at least the record's TTL plus grace, 5 min to 2 h.
const (
	domMin   = 5 * time.Minute
	domMax   = 2 * time.Hour
	domGrace = 30 * time.Second
)

// domainAddrs remembers which addresses DNS answered for which rule (by
// rule.key; a rule set swap keeps entries of rules that stay).
type domainAddrs struct {
	mu sync.Mutex
	m  map[netip.Addr]map[string]time.Time // addr -> rule name -> expiry
}

func (d *domainAddrs) add(ruleName string, resp *dns.Msg, now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.m == nil {
		d.m = map[netip.Addr]map[string]time.Time{}
	}
	for _, rr := range resp.Answer {
		var a netip.Addr
		switch v := rr.(type) {
		case *dns.A:
			a, _ = netip.AddrFromSlice(v.A.To4())
		case *dns.AAAA:
			a, _ = netip.AddrFromSlice(v.AAAA)
		default:
			continue
		}
		life := time.Duration(rr.Header().Ttl)*time.Second + domGrace
		life = min(max(life, domMin), domMax)
		if d.m[a] == nil {
			d.m[a] = map[string]time.Time{}
		}
		if exp := now.Add(life); exp.After(d.m[a][ruleName]) {
			d.m[a][ruleName] = exp
		}
	}
	if len(d.m) > 20000 { // prune now and then
		for a, rs := range d.m {
			for n, exp := range rs {
				if exp.Before(now) {
					delete(rs, n)
				}
			}
			if len(rs) == 0 {
				delete(d.m, a)
			}
		}
	}
}

func (d *domainAddrs) has(ruleName string, a netip.Addr, now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	exp, ok := d.m[a.Unmap()][ruleName]
	return ok && exp.After(now)
}

// ruleRoute returns the route of the first destination rule matching, or "".
func (e *Engine) ruleRoute(app string, proto int, dst netip.AddrPort) (string, string) {
	now := time.Now()
	e.mu.RLock()
	defer e.mu.RUnlock()
	for i := range e.rules {
		r := &e.rules[i]
		byDomain := len(r.domains) > 0 && e.domains.has(r.key, dst.Addr(), now)
		if r.matches(app, proto, dst, byDomain) {
			return r.route, r.name
		}
	}
	return "", ""
}

// matchNetwork returns the first profile for link/ssid, or nil.
func matchNetwork(ns []networkConf, link, ssid string) *networkConf {
	for i, n := range ns {
		if n.Link != "" && n.Link != link {
			continue
		}
		if len(n.SSID) > 0 && (ssid == "" || !contains(n.SSID, ssid)) {
			continue
		}
		return &ns[i]
	}
	return nil
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// SetNetwork tells the engine which network the device is on (link: wifi,
// mobile, ethernet or ""; ssid: Wi-Fi name, "" if unknown) and returns the
// name of the matching profile ("" = none). New connections follow the
// profile's default route and direct DNS.
//
// Running connections on the old default route are cut when the default
// changes (and direct DNS flows when the direct DNS server changes): on a
// profile that blocks, nothing may keep going the old way.
func (e *Engine) SetNetwork(link, ssid string) string {
	e.mu.Lock()
	oldDef, oldDirect, oldLink := e.def, e.direct, e.link
	e.link, e.ssid = link, ssid
	name := e.applyNetwork()
	newDef, newDirect := e.def, e.direct
	e.mu.Unlock()
	n := 0
	if newDef != oldDef || newDirect != oldDirect || link != oldLink {
		n = e.cut(func(f *flow) bool {
			return (f.byDefault && newDef != oldDef) || (f.isDNS(e) && f.route == RouteDirect && newDirect != oldDirect) ||
				(f.viaLink != "" && link != oldLink)
		})
	}
	e.logf("network %s %q: profile %q, %d connection(s) cut", link, ssid, name, n)
	return name
}

// applyNetwork picks def and direct from the profile of the current
// network. e.mu held.
func (e *Engine) applyNetwork() string {
	e.def, e.direct = e.baseDef, e.baseDirect
	n := matchNetwork(e.networks, e.link, e.ssid)
	if n == nil {
		e.netName = ""
		return ""
	}
	if n.Default != "" {
		e.def = n.Default
	}
	if a, err := netip.ParseAddr(n.DirectDNS); err == nil {
		e.direct = a
	}
	e.netName = n.Name
	return n.Name
}

// directDNS is the DNS server of the direct route now.
func (e *Engine) directDNS() netip.Addr {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.direct
}
