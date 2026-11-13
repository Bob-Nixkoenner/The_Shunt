package dnsproxy

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
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
		r := p.handle(port, q, markUnknown, nil)
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
		return p.handle(port, q, markUnknown, nil).Rcode
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

	// the login port: a query whose packet mark is known to come from the
	// login browser is not filtered; one without a readable mark (TCP, any
	// local process) is filtered like the direct route
	askMark := func(port int, name string, mark uint32) int {
		q := new(dns.Msg)
		q.SetQuestion(name, dns.TypeA)
		return p.handle(port, q, mark, nil).Rcode
	}
	if got := askMark(2, "x.ads.example.", 0); got != dns.RcodeSuccess {
		t.Errorf("login port, marked: rcode %d", got)
	}
	if got := askMark(2, "x.ads.example.", markUnknown); got != dns.RcodeNameError {
		t.Errorf("login port, no readable mark: rcode %d", got)
	}
	// per app: the sender is asked only for blocked queries
	p.Owner = func(string, netip.AddrPort) string { return "never called" }
	asked := 0
	who := func() string { asked++; return "firefox" }
	for _, n := range []string{"a.ads.example.", "b.ads.example.", "fine.example."} {
		q := new(dns.Msg)
		q.SetQuestion(n, dns.TypeA)
		p.handle(1, q, markUnknown, who)
	}
	st = p.FilterStats()
	if asked != 2 || st.ByApp["firefox"] != 2 || st.Recent[0].App != "firefox" {
		t.Errorf("per app: asked %d, stats %+v", asked, st)
	}
}

// A query that reaches another route's listener (the nat redirect is sticky
// per conntrack entry) is answered for the route its packet was marked for.
func TestWrongListener(t *testing.T) {
	direct := &engine.Route{Route: config.Route{Kind: config.RouteDirect}, Mark: engine.MarkDirect, DNSPort: 1}
	vps := &engine.Route{Route: config.Route{Kind: config.RouteTunnel, Tunnel: "vps"}, Mark: engine.MarkBase | 1, DNSPort: 3}
	plan := &engine.Plan{DNS: true, Routes: []*engine.Route{direct, vps}}
	p := New(slog.New(slog.NewTextHandler(io.Discard, nil)), &recWriter{adds: map[string]int{}})
	p.plan, p.byPort = plan, map[int]*engine.Route{1: direct, 3: vps}
	p.upstreams = RouteUpstreams{"direct": {tagUpstream("direct")}, "tunnel:vps": {tagUpstream("vps")}}
	ask := func(port int, mark uint32) string {
		q := new(dns.Msg)
		q.SetQuestion("x.example.", dns.TypeTXT)
		r := p.handle(port, q, mark, nil)
		if len(r.Answer) == 0 {
			return fmt.Sprintf("rcode %d", r.Rcode)
		}
		return r.Answer[0].(*dns.TXT).Txt[0]
	}
	for _, c := range []struct {
		port int
		mark uint32
		want string
	}{
		{1, markUnknown, "direct"},       // old kernel: the listener decides
		{1, 0, "direct"},                 // unmarked = direct
		{1, engine.MarkBase | 1, "vps"},  // tunnel app, redirected to the direct listener
		{3, 0, "direct"},                 // direct program, redirected to the tunnel listener
		{3, engine.MarkBase | 1, "vps"},  // as intended
		{3, engine.MarkBlock, "rcode 3"}, // blocked: name error
	} {
		if got := ask(c.port, c.mark); got != c.want {
			t.Errorf("port %d mark %#x: %s, want %s", c.port, c.mark, got, c.want)
		}
	}
}

func TestIsOnion(t *testing.T) {
	for n, want := range map[string]bool{"abc.onion": true, "onion": true, "a.b.onion": true, "onion.com": false, "notonion": false, "x.onions": false} {
		if isOnion(n) != want {
			t.Errorf("%q: want %v", n, want)
		}
	}
}

// M04: a query of an app whose rule points to a dead tunnel must never be
// answered by the default tunnel, whichever listener the redirect picked
// (conntrack reuse) and whatever mark the packet carries.
func TestDeadTunnelQueryStaysOffDefault(t *testing.T) {
	def := &engine.Route{Route: config.Route{Kind: config.RouteTunnel, Tunnel: "intern"}, DNSPort: 1, Mark: engine.MarkBase | 1}
	dead := &engine.Route{Route: config.Route{Kind: config.RouteTunnel, Tunnel: "dead"}, DNSPort: 2, Mark: engine.MarkBase | 2}
	direct := &engine.Route{Route: config.Route{Kind: config.RouteDirect}, DNSPort: 3, Mark: engine.MarkDirect}
	plan := &engine.Plan{DNS: true, Routes: []*engine.Route{def, dead, direct}}
	p := New(slog.New(slog.NewTextHandler(io.Discard, nil)), &recWriter{adds: map[string]int{}})
	p.plan, p.byPort = plan, map[int]*engine.Route{1: def, 2: dead, 3: direct}
	p.upstreams = RouteUpstreams{"tunnel:intern": {tagUpstream("intern")}, "direct": {tagUpstream("direct")}} // dead: none
	ask := func(port int, mark uint32) string {
		q := new(dns.Msg)
		q.SetQuestion("m04-x.example.", dns.TypeTXT)
		r := p.handle(port, q, mark, nil)
		if len(r.Answer) == 0 {
			return fmt.Sprintf("rcode%d", r.Rcode)
		}
		return r.Answer[0].(*dns.TXT).Txt[0]
	}
	for _, c := range []struct {
		name string
		port int
		mark uint32
		got  string
	}{
		{"own listener", 2, dead.Mark, "rcode2"},
		{"redirected to the default listener", 1, dead.Mark, "rcode2"},
		{"unknown shunt mark at the default listener", 1, engine.MarkBase | 9, "rcode2"},
		{"bypass mark at the default listener", 1, engine.MarkBypass, "rcode2"},
		{"default's own query", 1, def.Mark, "intern"},
	} {
		if got := ask(c.port, c.mark); got != c.got {
			t.Errorf("%s: got %s, want %s", c.name, got, c.got)
		}
	}
}

type obsRec struct {
	qs []string
}

func (o *obsRec) Query(c netip.Addr, name, qt string) {
	o.qs = append(o.qs, c.String()+" "+name+" "+qt)
}
func (o *obsRec) Answer(name string, addrs []netip.Addr) {}

type fakeRW struct{ got *dns.Msg }

func (f *fakeRW) LocalAddr() net.Addr         { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53} }
func (f *fakeRW) RemoteAddr() net.Addr        { return &net.UDPAddr{IP: net.ParseIP("192.0.2.7"), Port: 4000} }
func (f *fakeRW) WriteMsg(m *dns.Msg) error   { f.got = m; return nil }
func (f *fakeRW) Write(b []byte) (int, error) { return len(b), nil }
func (f *fakeRW) Close() error                { return nil }
func (f *fakeRW) TsigStatus() error           { return nil }
func (f *fakeRW) TsigTimersOnly(bool)         {}
func (f *fakeRW) Hijack()                     {}

// The optional observer sees each question; without one the proxy answers
// the same.
func TestObserver(t *testing.T) {
	direct := &engine.Route{Route: config.Route{Kind: config.RouteDirect}, DNSPort: 1}
	plan := &engine.Plan{DNS: true, Routes: []*engine.Route{direct}}
	p := New(slog.New(slog.NewTextHandler(io.Discard, nil)), &recWriter{adds: map[string]int{}})
	p.plan, p.byPort = plan, map[int]*engine.Route{1: direct}
	p.upstreams = RouteUpstreams{"direct": {tagUpstream("dns.direct")}}
	q := new(dns.Msg)
	q.SetQuestion("Sub.Example.Test.", dns.TypeTXT)
	w := &fakeRW{}
	p.serve(1, w, q)
	if w.got == nil || len(w.got.Answer) != 1 {
		t.Fatal("no answer without observer")
	}
	o := &obsRec{}
	p.Observer = o
	w = &fakeRW{}
	p.serve(1, w, q)
	if w.got == nil || len(w.got.Answer) != 1 {
		t.Fatal("no answer with observer")
	}
	if len(o.qs) != 1 || o.qs[0] != "192.0.2.7 sub.example.test TXT" {
		t.Fatalf("observer saw %v", o.qs)
	}
}

type aUpstream string

func (a aUpstream) Exchange(_ context.Context, m *dns.Msg) (*dns.Msg, error) {
	r := new(dns.Msg)
	r.SetReply(m)
	r.Answer = append(r.Answer, &dns.A{Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP(string(a))})
	return r, nil
}
func (a aUpstream) String() string { return "a" }

type rebindRec struct {
	obsRec
	drop bool
	seen []string
}

func (r *rebindRec) Rebind(name string, addrs []netip.Addr) bool {
	r.seen = append(r.seen, name+" "+addrs[0].String())
	return r.drop
}

// An observer that also implements Rebinder can have an answer dropped; a
// plain observer and no observer leave the answer alone.
func TestRebinder(t *testing.T) {
	direct := &engine.Route{Route: config.Route{Kind: config.RouteDirect}, DNSPort: 1}
	plan := &engine.Plan{DNS: true, Routes: []*engine.Route{direct}}
	p := New(slog.New(slog.NewTextHandler(io.Discard, nil)), &recWriter{adds: map[string]int{}})
	p.plan, p.byPort = plan, map[int]*engine.Route{1: direct}
	p.upstreams = RouteUpstreams{"direct": {aUpstream("192.0.2.9")}}
	q := new(dns.Msg)
	q.SetQuestion("rebind.example.test.", dns.TypeA)
	ask := func() *dns.Msg {
		w := &fakeRW{}
		p.serve(1, w, q)
		return w.got
	}
	if r := ask(); len(r.Answer) != 1 {
		t.Fatal("no observer")
	}
	p.Observer = &obsRec{}
	if r := ask(); len(r.Answer) != 1 {
		t.Fatal("plain observer")
	}
	rb := &rebindRec{}
	p.Observer = rb
	if r := ask(); len(r.Answer) != 1 || len(rb.seen) != 1 || rb.seen[0] != "rebind.example.test 192.0.2.9" {
		t.Fatalf("report only: %v", rb.seen)
	}
	rb.drop = true
	if r := ask(); len(r.Answer) != 0 || r.Rcode != dns.RcodeRefused {
		t.Fatalf("dropped answer expected, got rcode %d with %d records", r.Rcode, len(r.Answer))
	}
}

// seenUpstream records the ID it was asked with and answers as told.
type seenUpstream struct {
	id    *uint16
	other string // answer for this name instead of the asked one
}

func (s seenUpstream) Exchange(_ context.Context, m *dns.Msg) (*dns.Msg, error) {
	*s.id = m.Id
	r := new(dns.Msg)
	r.SetReply(m)
	name := m.Question[0].Name
	if s.other != "" {
		r.Question[0].Name, name = s.other, s.other
	}
	r.Answer = append(r.Answer, &dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP("192.0.2.5")})
	return r, nil
}
func (s seenUpstream) String() string { return "seen" }

// The upstream gets its own random ID, and an answer to another question is
// not passed on.
func TestUpstreamIDAndQuestionChecked(t *testing.T) {
	direct := &engine.Route{Route: config.Route{Kind: config.RouteDirect}, DNSPort: 1}
	plan := &engine.Plan{DNS: true, Routes: []*engine.Route{direct}}
	p := New(slog.New(slog.NewTextHandler(io.Discard, nil)), &recWriter{adds: map[string]int{}})
	p.plan, p.byPort = plan, map[int]*engine.Route{1: direct}
	var id uint16
	p.upstreams = RouteUpstreams{"direct": {seenUpstream{id: &id}}}
	q := new(dns.Msg)
	q.SetQuestion("one.example.test.", dns.TypeA)
	q.Id = 0x1234
	w := &fakeRW{}
	p.serve(1, w, q)
	if w.got.Id != 0x1234 || len(w.got.Answer) != 1 {
		t.Fatalf("client answer: id %x, %d records", w.got.Id, len(w.got.Answer))
	}
	same := 0
	for i := 0; i < 8; i++ {
		p.serve(1, &fakeRW{}, q)
		if id == 0x1234 {
			same++
		}
	}
	if same > 1 {
		t.Fatal("upstream was asked with the client's ID")
	}
	p.upstreams = RouteUpstreams{"direct": {seenUpstream{id: &id, other: "evil.example.test."}}}
	w = &fakeRW{}
	p.serve(1, w, q)
	if w.got.Rcode != dns.RcodeServerFailure || len(w.got.Answer) != 0 {
		t.Fatalf("answer to another question passed: rcode %d, %d records", w.got.Rcode, len(w.got.Answer))
	}
}
