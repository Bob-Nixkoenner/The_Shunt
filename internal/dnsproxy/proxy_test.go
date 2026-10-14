package dnsproxy

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/blocklist"
	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/Bob-Nixkoenner/the_shunt/internal/engine"
	"github.com/miekg/dns"
)

func TestRoutable(t *testing.T) {
	for s, want := range map[string]bool{
		"0.0.0.0": false, "0.1.2.3": false, "127.0.0.1": false, "169.254.1.1": false,
		"224.0.0.1": false, "255.255.255.255": false, "::": false, "::1": false, "fe80::1": false,
		"ff02::1": false, "::ffff:127.0.0.1": false,
		"93.184.216.34": true, "192.168.1.10": true, "10.0.0.1": true, "2606:4700::1": true,
	} {
		if got := Routable(netip.MustParseAddr(s)); got != want {
			t.Errorf("%s: got %v", s, got)
		}
	}
}

type tagUpstream string

func (t tagUpstream) Exchange(_ context.Context, m *dns.Msg) (*dns.Msg, error) {
	r := new(dns.Msg)
	r.SetReply(m)
	r.Answer = append(r.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET}, Txt: []string{string(t)}})
	return r, nil
}
func (t tagUpstream) String() string { return string(t) }

// The login browser asks the network's resolvers, never dns.direct, and
// domain rules don't apply to it.
func TestCaptiveUpstream(t *testing.T) {
	direct := &engine.Route{Route: config.Route{Kind: config.RouteDirect}, DNSPort: 1}
	captive := &engine.Route{Route: config.Route{Kind: config.RouteDirect}, DNSPort: 2, Captive: true}
	vps := &engine.Route{Route: config.Route{Kind: config.RouteTunnel, Tunnel: "vps"}, DNSPort: 3}
	plan := &engine.Plan{DNS: true, Routes: []*engine.Route{direct, vps}, Captive: captive,
		Rules: []engine.Rule{{Name: "d", Domains: []string{"login.example"}, Route: vps}}}
	p := New(slog.New(slog.NewTextHandler(io.Discard, nil)), &recWriter{adds: map[string]int{}})
	p.plan, p.byPort = plan, map[int]*engine.Route{1: direct, 2: captive, 3: vps}
	p.upstreams = RouteUpstreams{"direct": {tagUpstream("dns.direct")}, CaptiveUpstreams: {tagUpstream("network")}, "tunnel:vps": {tagUpstream("vps")}}
	ask := func(port int, name string) string {
		q := new(dns.Msg)
		q.SetQuestion(name, dns.TypeTXT)
		r := p.handle(port, q)
		if len(r.Answer) == 0 {
			return "none"
		}
		return r.Answer[0].(*dns.TXT).Txt[0]
	}
	if got := ask(2, "portal.example."); got != "network" {
		t.Errorf("login browser asked %s", got)
	}
	if got := ask(2, "login.example."); got != "network" {
		t.Errorf("domain rule applied to the login browser: %s", got)
	}
	if got := ask(1, "portal.example."); got != "dns.direct" {
		t.Errorf("direct asked %s", got)
	}
}

// Blocked names never reach an upstream; domain rules and the login
// browser are not filtered; each listener filters at its own level.
func TestFilter(t *testing.T) {
	direct := &engine.Route{Route: config.Route{Kind: config.RouteDirect}, DNSPort: 1, Filter: "normal"}
	off := &engine.Route{Route: config.Route{Kind: config.RouteDirect}, DNSPort: 4, Filter: "off"}
	captive := &engine.Route{Route: config.Route{Kind: config.RouteDirect}, DNSPort: 2, Captive: true, Filter: "off"}
	vps := &engine.Route{Route: config.Route{Kind: config.RouteTunnel, Tunnel: "vps"}, DNSPort: 3, Filter: "paranoid"}
	plan := &engine.Plan{DNS: true, Routes: []*engine.Route{direct, vps}, Captive: captive,
		Rules: []engine.Rule{{Name: "d", Domains: []string{"routed.ads.example"}, Route: vps}}}
	p := New(slog.New(slog.NewTextHandler(io.Discard, nil)), &recWriter{adds: map[string]int{}})
	p.plan, p.byPort = plan, map[int]*engine.Route{1: direct, 2: captive, 3: vps, 4: off}
	p.upstreams = RouteUpstreams{"direct": {tagUpstream("direct")}, CaptiveUpstreams: {tagUpstream("network")}, "tunnel:vps": {tagUpstream("vps")}}
	ads, _ := blocklist.Parse("ads", strings.NewReader("||ads.example^\n"))
	mal, _ := blocklist.Parse("mal", strings.NewReader("||evil.example^\n"))
	p.SetFilter(blocklist.NewFilter(map[string][]*blocklist.List{"normal": {ads}, "paranoid": {ads, mal}}, nil))
	ask := func(port int, name string) int {
		q := new(dns.Msg)
		q.SetQuestion(name, dns.TypeA)
		return p.handle(port, q).Rcode
	}
	for _, c := range []struct {
		port int
		name string
		want int
	}{
		{1, "x.ads.example.", dns.RcodeNameError},
		{1, "evil.example.", dns.RcodeSuccess},
		{3, "evil.example.", dns.RcodeNameError},
		{4, "x.ads.example.", dns.RcodeSuccess},
		{2, "x.ads.example.", dns.RcodeSuccess},
		{1, "routed.ads.example.", dns.RcodeSuccess},
	} {
		if got := ask(c.port, c.name); got != c.want {
			t.Errorf("port %d %s: rcode %d", c.port, c.name, got)
		}
	}
	st := p.FilterStats()
	if st.Blocked != 2 || st.ByLevel["paranoid"] != 1 || len(st.Recent) != 2 || st.Recent[0].Name != "evil.example" || st.Recent[0].List != "mal" {
		t.Errorf("stats %+v", st)
	}
}
