package defense

import (
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// udp4 builds an IPv4 + UDP packet from src (documentation ranges only).
func udp4(src string, sp, dp uint16, payload []byte) []byte {
	ip := net.ParseIP(src).To4()
	p := make([]byte, 28+len(payload))
	p[0], p[8], p[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	copy(p[12:16], ip)
	copy(p[16:20], net.IPv4(224, 0, 0, 251).To4())
	binary.BigEndian.PutUint16(p[20:], sp)
	binary.BigEndian.PutUint16(p[22:], dp)
	binary.BigEndian.PutUint16(p[24:], uint16(8+len(payload)))
	copy(p[28:], payload)
	return p
}

// dhcpClient builds a DHCP DISCOVER/REQUEST payload with options.
func dhcpClient(ciaddr string, opts ...[]byte) []byte {
	p := make([]byte, 240)
	p[0] = 1
	copy(p[12:16], net.ParseIP(ciaddr).To4())
	copy(p[236:240], []byte{0x63, 0x82, 0x53, 0x63})
	p = append(p, 53, 1, 3)
	for _, o := range opts {
		p = append(p, o...)
	}
	return append(p, 255)
}

func hopt(code byte, v string) []byte { return append([]byte{code, byte(len(v))}, v...) }

func mdnsAnswer(name string, ip string) []byte {
	m := new(dns.Msg)
	m.Response = true
	m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120}, A: net.ParseIP(ip).To4()}}
	b, _ := m.Pack()
	return b
}

func TestNameFromDHCPRequest(t *testing.T) {
	zero := netip.MustParseAddr("0.0.0.0")
	// requested address (option 50), host name (option 12)
	pl := dhcpClient("0.0.0.0", hopt(12, "kitchen-printer"), []byte{50, 4, 192, 0, 2, 44})
	c, ok := ParseDHCPClientName(pl, zero)
	if !ok || c.Name != "kitchen-printer" || c.Addr != netip.MustParseAddr("192.0.2.44") || c.Source != NameDHCP {
		t.Fatalf("%+v %v", c, ok)
	}
	// ciaddr wins
	c, ok = ParseDHCPClientName(dhcpClient("192.0.2.9", hopt(12, "laptop")), zero)
	if !ok || c.Addr != netip.MustParseAddr("192.0.2.9") {
		t.Fatalf("%+v", c)
	}
	// no name, no address, replies, truncation: nothing
	for _, bad := range [][]byte{dhcpClient("192.0.2.9"), dhcpClient("0.0.0.0", hopt(12, "x")), nil, make([]byte, 100), dhcpClient("192.0.2.9", hopt(12, "abc"))[:245]} {
		if _, ok := ParseDHCPClientName(bad, zero); ok {
			t.Fatal("accepted garbage")
		}
	}
	reply := dhcpClient("192.0.2.9", hopt(12, "x"))
	reply[0] = 2
	if _, ok := ParseDHCPClientName(reply, zero); ok {
		t.Fatal("server reply accepted")
	}
}

func TestNameIsCleanedAndCut(t *testing.T) {
	long := strings.Repeat("a", 200)
	pl := dhcpClient("192.0.2.9", hopt(12, "ev\x00il\n<b>"+long))
	c, ok := ParseDHCPClientName(pl, netip.Addr{})
	if !ok || len(c.Name) > MaxNameLen || strings.ContainsAny(c.Name, "\x00\n") {
		t.Fatalf("%q", c.Name)
	}
	if CleanText("a‮b\x07c", 10) != "abc" {
		t.Fatalf("%q", CleanText("a‮b\x07c", 10))
	}
}

func TestMDNSNameOnlyForOwnAddress(t *testing.T) {
	src := netip.MustParseAddr("192.0.2.30")
	got := ParseMDNSNames(mdnsAnswer("living-room-tv.local.", "192.0.2.30"), src, false)
	if len(got) != 1 || got[0].Name != "living-room-tv" || got[0].Source != NameMDNS || got[0].Addr != src {
		t.Fatalf("%+v", got)
	}
	// a record about another address (forged claim) and non-.local names are ignored
	if g := ParseMDNSNames(mdnsAnswer("boss-pc.local.", "192.0.2.99"), src, false); len(g) != 0 {
		t.Fatalf("foreign claim accepted: %+v", g)
	}
	if g := ParseMDNSNames(mdnsAnswer("www.example.net.", "192.0.2.30"), src, false); len(g) != 0 {
		t.Fatalf("non-local name accepted: %+v", g)
	}
	// LLMNR answers carry plain labels
	if g := ParseMDNSNames(mdnsAnswer("desktop.", "192.0.2.30"), src, true); len(g) != 1 || g[0].Source != NameLLMNR {
		t.Fatalf("%+v", g)
	}
	// a query is no announcement; garbage never panics
	q := new(dns.Msg)
	q.SetQuestion("x.local.", dns.TypeA)
	qb, _ := q.Pack()
	if g := ParseMDNSNames(qb, src, false); len(g) != 0 {
		t.Fatal("query accepted")
	}
	for i := 0; i < 20; i++ {
		ParseMDNSNames(append([]byte{0, 0, 0x84, 0}, make([]byte, i*3)...), src, false)
	}
}

func TestNamesFromIPv4(t *testing.T) {
	dh := udp4("0.0.0.0", 68, 67, dhcpClient("0.0.0.0", hopt(12, "tablet"), []byte{50, 4, 192, 0, 2, 7}))
	if c := NamesFromIPv4(dh); len(c) != 1 || c[0].Name != "tablet" || c[0].Addr != netip.MustParseAddr("192.0.2.7") {
		t.Fatalf("%+v", c)
	}
	md := udp4("192.0.2.30", 5353, 5353, mdnsAnswer("tv.local.", "192.0.2.30"))
	if c := NamesFromIPv4(md); len(c) != 1 || c[0].Name != "tv" {
		t.Fatalf("%+v", c)
	}
	frag := append([]byte{}, md...)
	frag[6] = 0x20 // more fragments
	if NamesFromIPv4(frag) != nil || NamesFromIPv4(md[:20]) != nil || NamesFromIPv4(nil) != nil {
		t.Fatal("fragment or short packet accepted")
	}
}

func TestNameCacheLimitsAndRank(t *testing.T) {
	c := NewNameCache()
	clk := newClock()
	c.now = clk.Now
	a := netip.MustParseAddr("192.0.2.1")
	c.Set(a, "from-mdns", NameMDNS)
	c.Set(a, "from-dhcp", NameDHCP) // worse source does not replace a fresh better one
	if n, _ := c.Get(a); n.Name != "from-mdns" {
		t.Fatal(n)
	}
	clk.Add(nameTTL + time.Second)
	if _, ok := c.Get(a); ok {
		t.Fatal("must expire")
	}
	for i := 0; i < maxNameCache+50; i++ {
		c.Set(netip.AddrFrom4([4]byte{198, 51, byte(i >> 8), byte(i)}), "n", NameDHCP)
	}
	if c.Len() > maxNameCache {
		t.Fatalf("cache grew to %d", c.Len())
	}
	c.Set(netip.MustParseAddr("0.0.0.0"), "x", NameDHCP)
	c.Set(netip.MustParseAddr("224.0.0.1"), "x", NameDHCP)
	c.Forget()
	if c.Len() != 0 {
		t.Fatal("forget")
	}
}

func TestManagerNamesInEventsAndOwnSkipped(t *testing.T) {
	m := scanManager(t, nil)
	m.ownAddr = func(a netip.Addr) bool { return a == netip.MustParseAddr("192.0.2.1") }
	m.LearnNames([]NameClaim{{netip.MustParseAddr("192.0.2.5"), "peer-box", NameMDNS}, {netip.MustParseAddr("192.0.2.1"), "me", NameDHCP}})
	m.Report(Event{Kind: KindDecoyHit, Severity: SevMedium, Src: "192.0.2.5", Port: 22})
	r := m.Events(0)
	if r.Names["192.0.2.5"].Name != "peer-box" || len(r.Names) != 1 {
		t.Fatalf("%+v", r.Names)
	}
	if m.EventsFor("192.0.2.5").Names["192.0.2.5"].Source != NameMDNS {
		t.Fatal("source detail")
	}
	m.SetNetwork("other", ClassUnknown)
	if m.Events(0).Names != nil {
		t.Fatal("names must be forgotten on a new network")
	}
}
