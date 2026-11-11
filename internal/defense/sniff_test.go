package defense

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestGWWatch(t *testing.T) {
	gw := netip.MustParseAddr("192.0.2.1")
	w := newGWWatch("192.0.2.1", "02:00:00:00:00:01")
	if _, hit := w.Feed(gw, "02:00:00:00:00:01"); hit {
		t.Fatal("same mac")
	}
	if _, hit := w.Feed(netip.MustParseAddr("192.0.2.77"), "02:00:00:00:00:99"); hit {
		t.Fatal("other host")
	}
	ev, hit := w.Feed(gw, "02:00:00:00:00:99")
	if !hit || ev.Kind != KindARP || ev.Severity != SevHigh {
		t.Fatalf("%+v", ev)
	}
	if _, hit := w.Feed(gw, "02:00:00:00:00:99"); hit {
		t.Fatal("must say it once")
	}
	w.Feed(gw, "02:00:00:00:00:01") // back to normal re-arms
	if _, hit := w.Feed(gw, "02:00:00:00:00:98"); !hit {
		t.Fatal("re-armed")
	}
	// no baseline: first MAC is learned, no alarm
	n := newGWWatch("192.0.2.1", "")
	if _, hit := n.Feed(gw, "02:00:00:00:00:05"); hit {
		t.Fatal("learn")
	}
	if _, hit := n.Feed(gw, "02:00:00:00:00:06"); !hit {
		t.Fatal("change after learning")
	}
}

func dhcpPacket(typ byte, server [4]byte) []byte {
	p := make([]byte, 240)
	p[0] = 2
	copy(p[236:], []byte{0x63, 0x82, 0x53, 0x63})
	p = append(p, 53, 1, typ, 54, 4)
	p = append(p, server[:]...)
	return append(p, 255)
}

func TestParseDHCPReplyAndWatch(t *testing.T) {
	a, ok := ParseDHCPReply(dhcpPacket(2, [4]byte{192, 0, 2, 1}))
	if !ok || a != netip.MustParseAddr("192.0.2.1") {
		t.Fatal(a, ok)
	}
	if _, ok := ParseDHCPReply(dhcpPacket(1, [4]byte{192, 0, 2, 1})); ok {
		t.Fatal("DISCOVER is not a reply")
	}
	if _, ok := ParseDHCPReply([]byte{1, 2, 3}); ok {
		t.Fatal("short")
	}
	bad := dhcpPacket(2, [4]byte{192, 0, 2, 1})
	bad[len(bad)-6] = 200 // option length beyond the packet
	if _, ok := ParseDHCPReply(bad); ok {
		t.Fatal("truncated option")
	}
	w := newDHCPWatch()
	if _, hit := w.Feed(a); hit {
		t.Fatal("one server")
	}
	if _, hit := w.Feed(a); hit {
		t.Fatal("same server")
	}
	ev, hit := w.Feed(netip.MustParseAddr("198.51.100.5"))
	if !hit || ev.Kind != KindRogueDHCP || ev.Src != "198.51.100.5" {
		t.Fatalf("%+v", ev)
	}
	if _, hit := w.Feed(netip.MustParseAddr("203.0.113.5")); hit {
		t.Fatal("once")
	}
}

// fakeDNS answers every A question with ip on a loopback UDP port.
func fakeDNS(t *testing.T, ip string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no loopback udp:", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1}, A: net.ParseIP(ip)})
		_ = w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	return pc.LocalAddr().String()
}

func TestDNSCheck(t *testing.T) {
	ref := func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("192.0.2.53")}, nil
	}
	good, evil := fakeDNS(t, "192.0.2.53"), fakeDNS(t, "198.51.100.66")
	ctx := context.Background()
	c := &DNSCheck{Reference: ref, Names: []string{"example.test"}, Public: good}
	if ev := c.Run(ctx, Env{DNS: []string{good}}); len(ev) != 0 {
		t.Fatalf("honest resolver: %+v", ev)
	}
	ev := c.Run(ctx, Env{DNS: []string{evil}})
	if len(ev) != 1 || ev[0].Kind != KindDNSHijack {
		t.Fatalf("lying local resolver: %+v", ev)
	}
	c.Public = evil // port 53 diverted
	if ev := c.Run(ctx, Env{DNS: []string{good}}); len(ev) != 1 {
		t.Fatalf("diverted: %+v", ev)
	}
	// dead resolver and failing reference are no findings
	c.Public = "127.0.0.1:1"
	if ev := c.Run(ctx, Env{DNS: []string{"127.0.0.1:1"}}); len(ev) != 0 {
		t.Fatalf("dead: %+v", ev)
	}
	if ev := (&DNSCheck{}).Run(ctx, Env{DNS: []string{evil}}); ev != nil {
		t.Fatal("no reference, no check")
	}
}

func TestTwinStore(t *testing.T) {
	p := filepath.Join(t.TempDir(), "twins.json")
	s := &TwinStore{Path: p}
	if s.Check("TestNet", "02:00:00:00:00:01") {
		t.Fatal("first sight")
	}
	if s.Check("TestNet", "02:00:00:00:00:01") {
		t.Fatal("same gateway")
	}
	if !s.Check("TestNet", "02:00:00:00:00:02") {
		t.Fatal("twin")
	}
	if s.Check("", "02:00:00:00:00:02") || s.Check("x", "") {
		t.Fatal("empty values")
	}
	// survives a restart; the file holds no readable name or MAC
	s2 := &TwinStore{Path: p}
	if s2.Check("TestNet", "02:00:00:00:00:01") {
		t.Fatal("known after reload")
	}
	raw, _ := readFile(p)
	for _, bad := range []string{"TestNet", "02:00:00"} {
		if contains(raw, bad) {
			t.Fatalf("plain %q in store", bad)
		}
	}
	_ = time.Now
}

func readFile(p string) (string, error) {
	b, err := os.ReadFile(p)
	return string(b), err
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }

func TestParseLoggedPacket(t *testing.T) {
	v4 := make([]byte, 24)
	v4[0], v4[9] = 0x45, 6
	copy(v4[12:], []byte{198, 51, 100, 9})
	v4[22], v4[23] = 0x01, 0xbb // dport 443
	a, pr, port, ok := ParseLoggedPacket(v4)
	if !ok || a != netip.MustParseAddr("198.51.100.9") || pr != "tcp" || port != 443 {
		t.Fatal(a, pr, port, ok)
	}
	v4[6] = 0x00
	v4[7] = 0x08 // fragment offset
	if _, _, _, ok := ParseLoggedPacket(v4); ok {
		t.Fatal("later fragment")
	}
	v6 := make([]byte, 44)
	v6[0], v6[6] = 0x60, 17
	copy(v6[8:], netip.MustParseAddr("2001:db8::5").AsSlice())
	v6[42], v6[43] = 0, 53
	a, pr, port, ok = ParseLoggedPacket(v6)
	if !ok || a != netip.MustParseAddr("2001:db8::5") || pr != "udp" || port != 53 {
		t.Fatal(a, pr, port, ok)
	}
	for _, bad := range [][]byte{nil, {0x45}, v6[:20], {0x10, 0, 0, 0}} {
		if _, _, _, ok := ParseLoggedPacket(bad); ok {
			t.Fatal("garbage accepted")
		}
	}
}

func TestDHCPDiscoverBuilders(t *testing.T) {
	d := BuildDHCPDiscover(0x01020304, [6]byte{0x02, 1, 2, 3, 4, 5})
	if d[0] != 1 || d[10] != 0x80 || d[4] != 1 || d[7] != 4 || d[239] != 0x63 {
		t.Fatalf("bad discover % x", d[:12])
	}
	if _, ok := ParseDHCPReply(d); ok {
		t.Fatal("a request is no reply")
	}
	ip := BuildDHCPIPv4(d)
	if len(ip) != 28+len(d) || ip[9] != 17 || ipChecksum(ip[:20]) != 0 {
		t.Fatalf("bad ip header, checksum %x", ipChecksum(ip[:20]))
	}
	if ip[22] != 0 || ip[23] != 67 || ip[20] != 0 || ip[21] != 68 {
		t.Fatal("ports")
	}
}

func TestDHCPTwoServersViaOffers(t *testing.T) {
	w := newDHCPWatch()
	a, _ := ParseDHCPReply(dhcpPacket(2, [4]byte{192, 0, 2, 1}))
	b, _ := ParseDHCPReply(dhcpPacket(2, [4]byte{192, 0, 2, 222}))
	if _, hit := w.Feed(a); hit {
		t.Fatal("one server is normal")
	}
	if _, hit := w.Feed(a); hit {
		t.Fatal("same server again")
	}
	if ev, hit := w.Feed(b); !hit || ev.Kind != KindRogueDHCP || ev.Src != "192.0.2.222" {
		t.Fatalf("second server not reported: %+v", ev)
	}
}

func TestDNSOnceFilter(t *testing.T) {
	var d dnsOnce
	e := []Event{{Detail: "x"}}
	if len(d.Filter(e)) != 1 || len(d.Filter(e)) != 0 {
		t.Fatal("report once")
	}
	d.Filter(nil)
	if len(d.Filter(e)) != 1 {
		t.Fatal("report again after clean run")
	}
}

func TestGWWatchPollBaselineAndChange(t *testing.T) {
	g := newGWWatch("192.0.2.1", "")
	gw, _ := netip.ParseAddr("192.0.2.1")
	if _, hit := g.Feed(gw, "02:00:00:00:00:01"); hit {
		t.Fatal("first MAC is the baseline")
	}
	for i := 0; i < 3; i++ { // periodic polling repeats the same entry
		if _, hit := g.Feed(gw, "02:00:00:00:00:01"); hit {
			t.Fatal("same MAC")
		}
	}
	if _, hit := g.Feed(gw, "02:00:00:00:00:99"); !hit {
		t.Fatal("changed MAC must report")
	}
	if _, hit := g.Feed(gw, "02:00:00:00:00:99"); hit {
		t.Fatal("report once")
	}
}

func TestProbeAllowed(t *testing.T) {
	cases := []struct {
		mode  string
		class Class
		quiet bool
		want  bool
	}{
		{"", ClassPublic, false, true},
		{"auto", ClassPublic, false, true},
		{"auto", ClassPublic, true, false},
		{"auto", ClassTrusted, false, false},
		{"auto", ClassManaged, false, false},
		{"on", ClassTrusted, true, true},
		{"on", ClassManaged, false, true},
		{"off", ClassPublic, false, false},
	}
	for _, c := range cases {
		if got := ProbeAllowed(c.mode, c.class, c.quiet); got != c.want {
			t.Errorf("mode %q class %s quiet %v: got %v", c.mode, c.class, c.quiet, got)
		}
	}
}

func dhcpWithOpts(opts ...[]byte) []byte {
	p := make([]byte, 240)
	p[0] = 2
	copy(p[236:], []byte{0x63, 0x82, 0x53, 0x63})
	p = append(p, 53, 1, 2, 54, 4, 192, 0, 2, 1)
	for _, o := range opts {
		p = append(p, o...)
	}
	return append(p, 255)
}

func opt(code byte, v ...byte) []byte { return append([]byte{code, byte(len(v))}, v...) }

func TestDHCPOptionsTunnelVision(t *testing.T) {
	// 0.0.0.0/1 and 128.0.0.0/1 via 192.0.2.99 (a host that is not the router)
	p := dhcpWithOpts(opt(3, 192, 0, 2, 1), opt(121, 1, 0, 192, 0, 2, 99, 1, 128, 192, 0, 2, 99), opt(15, 'x'), opt(252, 'u'))
	i, ok := ParseDHCPOptions(p)
	if !ok || i.RouteOpt != 121 || len(i.Routes) != 2 || !i.WPAD || !i.Domain {
		t.Fatalf("%+v %v", i, ok)
	}
	if i.Routes[0].Prefix.String() != "0.0.0.0/1" || i.Routes[1].Prefix.String() != "128.0.0.0/1" {
		t.Fatalf("%v", i.Routes)
	}
	w := newDHCPOptWatch()
	evs := w.Feed(i)
	if len(evs) != 1 || evs[0].Kind != KindDHCPOption || evs[0].Severity != SevHigh || evs[0].Src != "192.0.2.1" {
		t.Fatalf("%+v", evs)
	}
	if len(w.Feed(i)) != 0 {
		t.Fatal("same summary twice")
	}
}

func TestDHCPOptionsBenign(t *testing.T) {
	// /24 route plus a default via the offered router: informational only
	p := dhcpWithOpts(opt(3, 192, 0, 2, 1), opt(6, 198, 51, 100, 53), opt(121, 24, 198, 51, 100, 192, 0, 2, 7, 0, 192, 0, 2, 1))
	i, ok := ParseDHCPOptions(p)
	if !ok || len(i.Routes) != 2 || i.Routes[0].Prefix.String() != "198.51.100.0/24" {
		t.Fatalf("%+v", i)
	}
	if c, _ := i.Covering(); c {
		t.Fatal("benign routes flagged")
	}
	ev := newDHCPOptWatch().Feed(i)
	if len(ev) != 1 || ev[0].Severity != SevInfo || strings.Contains(ev[0].Detail, "192.0.2.7") {
		t.Fatalf("%+v", ev)
	}
	// default route to another host than option 3
	p = dhcpWithOpts(opt(3, 192, 0, 2, 1), opt(121, 0, 203, 0, 113, 5))
	i, _ = ParseDHCPOptions(p)
	if c, _ := i.Covering(); !c {
		t.Fatal("foreign default route must be flagged")
	}
	// option 249 is read like 121
	i, _ = ParseDHCPOptions(dhcpWithOpts(opt(249, 7, 10, 0, 0, 0, 1, 1, 1)))
	if i.RouteOpt != 249 || len(i.Routes) != 1 || i.Routes[0].Prefix.String() != "10.0.0.0/7" {
		t.Fatalf("%+v", i)
	}
}

func TestDHCPOptionsMalformed(t *testing.T) {
	for _, o := range [][]byte{
		opt(121, 33, 1, 2, 3, 4, 5, 6, 7, 8), // width 33
		opt(121, 24, 1, 2),                   // truncated
		{121, 200, 1},                        // length beyond packet
	} {
		i, ok := ParseDHCPOptions(dhcpWithOpts(o))
		if ok && !i.Malformed {
			t.Fatalf("not flagged: %x", o)
		}
		if ok {
			if c, _ := i.Covering(); c {
				t.Fatalf("garbage must not count as covering: %x", o)
			}
		}
	}
	if _, ok := ParseDHCPOptions(dhcpWithOpts()[:100]); ok {
		t.Fatal("short")
	}
	// request (op 1) is not a reply
	p := dhcpWithOpts()
	p[0] = 1
	if _, ok := ParseDHCPOptions(p); ok {
		t.Fatal("op 1")
	}
}

func FuzzParseDHCPOptions(f *testing.F) {
	f.Add(dhcpWithOpts(opt(121, 1, 0, 192, 0, 2, 99)))
	f.Fuzz(func(t *testing.T, b []byte) { ParseDHCPOptions(b) })
}

func TestDNSRebindWithoutReference(t *testing.T) {
	ctx := context.Background()
	for _, addr := range []string{"198.18.0.7", "198.19.255.1", "10.0.0.9", "127.0.0.1"} {
		bad := fakeDNS(t, addr)
		c := &DNSCheck{Names: []string{"example.test"}, Public: "127.0.0.1:1"}
		ev, ok := c.RunStatus(ctx, Env{DNS: []string{bad}})
		if !ok || len(ev) != 1 || ev[0].Kind != KindDNSHijack {
			t.Fatalf("%s: %+v ok=%v", addr, ev, ok)
		}
	}
	// reference unreachable: still caught, but refOK=false
	failing := func(context.Context, string) ([]netip.Addr, error) { return nil, context.DeadlineExceeded }
	c := &DNSCheck{Reference: failing, Names: []string{"example.test"}, Public: "127.0.0.1:1"}
	ev, ok := c.RunStatus(ctx, Env{DNS: []string{fakeDNS(t, "198.18.0.7")}})
	if ok || len(ev) != 1 {
		t.Fatalf("failing ref: %+v ok=%v", ev, ok)
	}
	// a normal public answer without a reference is no finding
	if ev, _ := (&DNSCheck{Names: []string{"example.test"}, Public: "127.0.0.1:1"}).RunStatus(ctx, Env{DNS: []string{fakeDNS(t, "192.0.2.53")}}); len(ev) != 0 {
		t.Fatalf("honest: %+v", ev)
	}
}

func TestDNSSeriesRetry(t *testing.T) {
	var slept []time.Duration
	sleep := func(_ context.Context, d time.Duration) bool { slept = append(slept, d); return true }
	var got []Event
	emit := func(e Event) { got = append(got, e) }
	hit := Event{Kind: KindDNSHijack, Severity: SevHigh, Detail: "x"}

	// reference unreachable twice, then back and a hijack is found
	var once dnsOnce
	var noted bool
	n := 0
	dnsSeries(context.Background(), func() ([]Event, bool) {
		n++
		if n < 3 {
			return nil, false
		}
		return []Event{hit}, true
	}, sleep, emit, &once, &noted)
	if n != 3 || len(got) != 1 || got[0].Kind != KindDNSHijack || len(slept) != 2 || slept[0] != 2*time.Second || slept[1] != 5*time.Second {
		t.Fatalf("n=%d got=%+v slept=%v", n, got, slept)
	}

	// never reachable: one info observation per series, none on the second
	got, slept, n = nil, nil, 0
	run := func() ([]Event, bool) { n++; return nil, false }
	dnsSeries(context.Background(), run, sleep, emit, &once, &noted)
	if n != len(dnsBackoff)+1 || len(got) != 1 || got[0].Kind != KindObservation || got[0].Severity != SevInfo || got[0].Detail != DNSRetryNote {
		t.Fatalf("n=%d got=%+v", n, got)
	}
	dnsSeries(context.Background(), run, sleep, emit, &once, &noted)
	if len(got) != 1 {
		t.Fatalf("note repeated: %+v", got)
	}
	var total time.Duration
	for _, d := range dnsBackoff {
		total += d
	}
	if total > 60*time.Second {
		t.Fatal("series longer than 60 s")
	}

	// context ends during backoff: stop, no note
	got = nil
	noted = false
	dnsSeries(context.Background(), run, func(context.Context, time.Duration) bool { return false }, emit, &once, &noted)
	if len(got) != 0 {
		t.Fatalf("aborted series noted: %+v", got)
	}
}
