package defense

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// DNS tunnel observation: the DNS proxy hands every query (name, type) to
// ObserveDNS. Queries are grouped per client and base domain (second-level
// name) over a sliding window and scored with DNSTunnelScore. Only the base
// domain and the score are reported, never the long sub-domain labels (they
// are what a tunnel hides data in).

const (
	dnsWindow      = 60 * time.Second
	dnsMaxKeep     = 64  // queries kept per client+domain
	dnsMaxKeys     = 512 // client+domain pairs tracked
	dnsThreshold   = 0.5 // score that raises the event
	dnsCooldown    = 10 * time.Minute
	dnsCacheMax    = 4096 // address -> name entries (first-seen)
	dnsCacheMaxAge = time.Hour
)

type dnsQ struct {
	q DNSQuery
	t time.Time
}

type dnsKey struct{ client, base string }

type dnsTrack struct {
	qs    []dnsQ
	fired time.Time
	app   string // program of the latest query ("" = unknown)
}

// dnsState is the Manager's DNS-side memory.
type dnsState struct {
	mu      sync.Mutex
	keys    map[dnsKey]*dnsTrack
	names   map[netip.Addr]nameAt // addresses the proxy answered with
	rebound map[string]time.Time  // base domain -> last rebind event
}

type nameAt struct {
	base string
	at   time.Time
}

// twoPartSuffixes: public suffixes with two labels that the simple
// "last two labels" rule would cut wrongly. Not the full public suffix list:
// a tunnel on an uncommon suffix is grouped one label too high, which only
// merges more queries into one group.
var twoPartSuffixes = map[string]bool{
	"co.uk": true, "org.uk": true, "ac.uk": true, "gov.uk": true, "com.au": true, "net.au": true,
	"co.jp": true, "co.nz": true, "co.za": true, "com.br": true, "com.cn": true, "co.in": true,
}

// BaseDomain returns the second-level domain of name ("a.b.example.com" ->
// "example.com"). Names with one label are returned as they are.
func BaseDomain(name string) string {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	parts := strings.Split(name, ".")
	n := len(parts)
	if n <= 2 {
		return name
	}
	if twoPartSuffixes[strings.Join(parts[n-2:], ".")] && n >= 3 {
		return strings.Join(parts[n-3:], ".")
	}
	return strings.Join(parts[n-2:], ".")
}

// Query and Answer let the manager serve as the DNS proxy's observer
// (dnsproxy.Observer) without either package importing the other.
func (m *Manager) Query(client netip.Addr, name, qtype string) { m.ObserveDNS(client, name, qtype) }

// Answer: see Query.
func (m *Manager) Answer(name string, addrs []netip.Addr) { m.ObserveDNSAnswer(name, addrs) }

// ObserveDNS is called by the DNS proxy for every query. It is cheap and
// does nothing while the dns_tunnel feature is off.
func (m *Manager) ObserveDNS(client netip.Addr, name, qtype string) {
	m.ObserveDNSApp(client, "", name, qtype)
}

// QueryApp is Query with the program that asked ("" = unknown); the event
// names it, so a program that goes around the tunnel can be found.
func (m *Manager) QueryApp(client netip.Addr, app, name, qtype string) {
	m.ObserveDNSApp(client, app, name, qtype)
}

// searchSuffixes end names that a resolver appends (search domain) or that
// only exist in the local network. They are cut off before the base domain
// is taken, else "example.com" asked with a ".lan" search domain would be
// tracked as the domain "com.lan".
var searchSuffixes = []string{".home.arpa", ".localdomain", ".internal", ".intranet", ".private", ".corp", ".lan", ".local", ".home", ".fritz.box"}

// StripLocalSuffix removes a local or search suffix. ok is false when
// nothing public is left (a purely local name such as "printer.lan").
func StripLocalSuffix(name string) (string, bool) {
	n := strings.TrimSuffix(strings.ToLower(name), ".")
	for _, suf := range searchSuffixes {
		if strings.HasSuffix(n, suf) {
			rest := strings.TrimSuffix(n, suf)
			return rest, strings.Contains(rest, ".")
		}
	}
	return n, true
}

// ObserveDNSApp is ObserveDNS with the asking program.
func (m *Manager) ObserveDNSApp(client netip.Addr, app, name, qtype string) {
	if !m.feature(FeatDNSTunnel).Watch {
		return
	}
	name, pub := StripLocalSuffix(name)
	if !pub {
		return
	}
	base := BaseDomain(name)
	if base == "" || !strings.Contains(base, ".") {
		return // "localhost", single labels, the root
	}
	now := m.now()
	k := dnsKey{client.Unmap().String(), base}
	m.dns.mu.Lock()
	if m.dns.keys == nil {
		m.dns.keys = map[dnsKey]*dnsTrack{}
	}
	tr := m.dns.keys[k]
	if tr == nil {
		if len(m.dns.keys) >= dnsMaxKeys {
			m.pruneDNSLocked(now)
			if len(m.dns.keys) >= dnsMaxKeys {
				m.dns.mu.Unlock()
				return
			}
		}
		tr = &dnsTrack{}
		m.dns.keys[k] = tr
	}
	keep := tr.qs[:0]
	for _, x := range tr.qs {
		if now.Sub(x.t) <= dnsWindow {
			keep = append(keep, x)
		}
	}
	tr.qs = append(keep, dnsQ{DNSQuery{Name: name, Type: qtype}, now})
	if app != "" {
		tr.app = app
	}
	if len(tr.qs) > dnsMaxKeep {
		tr.qs = tr.qs[len(tr.qs)-dnsMaxKeep:]
	}
	var fire bool
	var score float64
	if tr.fired.IsZero() || now.Sub(tr.fired) >= dnsCooldown {
		qs := make([]DNSQuery, len(tr.qs))
		for i, x := range tr.qs {
			qs[i] = x.q
		}
		if score = DNSTunnelScore(qs); score >= dnsThreshold {
			tr.fired, fire = now, true
		}
	}
	count, who := len(tr.qs), tr.app
	m.dns.mu.Unlock()
	if fire {
		m.Report(Event{Kind: KindDNSTunnel, Severity: SevMedium,
			Detail: fmt.Sprintf("domain=%s score=%.2f queries=%d window=%ds", base, score, count, int(dnsWindow/time.Second)) + appDetail(who)})
	}
}

func (m *Manager) pruneDNSLocked(now time.Time) {
	for k, tr := range m.dns.keys {
		if len(tr.qs) == 0 || now.Sub(tr.qs[len(tr.qs)-1].t) > dnsWindow {
			delete(m.dns.keys, k)
		}
	}
}

// ObserveDNSAnswer remembers which base domain an address was answered for
// (the first-seen check names a destination by its domain when it can).
func (m *Manager) ObserveDNSAnswer(name string, addrs []netip.Addr) {
	if len(addrs) == 0 {
		return
	}
	base := BaseDomain(name)
	if !strings.Contains(base, ".") {
		return
	}
	now := m.now()
	m.dns.mu.Lock()
	defer m.dns.mu.Unlock()
	if m.dns.names == nil {
		m.dns.names = map[netip.Addr]nameAt{}
	}
	if len(m.dns.names) >= dnsCacheMax {
		for a, v := range m.dns.names {
			if now.Sub(v.at) > dnsCacheMaxAge {
				delete(m.dns.names, a)
			}
		}
		if len(m.dns.names) >= dnsCacheMax {
			return
		}
	}
	for _, a := range addrs {
		m.dns.names[a.Unmap()] = nameAt{base, now}
	}
}

// domainOf returns the base domain the proxy last answered a for ("" = none).
func (m *Manager) domainOf(a netip.Addr) string {
	m.dns.mu.Lock()
	defer m.dns.mu.Unlock()
	v, ok := m.dns.names[a.Unmap()]
	if !ok || m.now().Sub(v.at) > dnsCacheMaxAge {
		return ""
	}
	return v.base
}

// forgetDNS drops the tracked queries (new network).
func (m *Manager) forgetDNS() {
	m.dns.mu.Lock()
	m.dns.keys = nil
	m.dns.rebound = nil
	m.dns.mu.Unlock()
}

func appDetail(app string) string {
	if app == "" {
		return ""
	}
	return " app=" + app
}
