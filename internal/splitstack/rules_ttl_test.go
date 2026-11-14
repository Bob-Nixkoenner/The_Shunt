package splitstack

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// M-02: an app must never cache a domain rule's answer longer than the
// address stays in the rule's set, or its traffic falls back to the default
// route once the entry is gone.
func TestDomainRuleClientTTLCapped(t *testing.T) {
	for _, ttl := range []uint32{0, 60, 3600, 7170, 7200, 86400, 1 << 31} {
		resp := new(dns.Msg)
		resp.SetQuestion("app.example.test.", dns.TypeA)
		resp.Response = true
		resp.Answer = []dns.RR{
			&dns.CNAME{Hdr: dns.RR_Header{Name: "app.example.test.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: ttl}, Target: "cdn.example.test."},
			&dns.A{Hdr: dns.RR_Header{Name: "cdn.example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}, A: net.ParseIP("192.0.2.10")},
			&dns.AAAA{Hdr: dns.RR_Header{Name: "cdn.example.test.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl}, AAAA: net.ParseIP("2001:db8::10")},
		}
		changed := capAnswerTTL(resp, domClientTTL)
		if changed != (ttl > domClientTTL) {
			t.Fatalf("ttl %d: changed=%v", ttl, changed)
		}
		// the packed answer the app gets carries the capped TTL
		b, err := resp.Pack()
		if err != nil {
			t.Fatal(err)
		}
		var got dns.Msg
		if err := got.Unpack(b); err != nil {
			t.Fatal(err)
		}
		var d domainAddrs
		now := time.Unix(1_000_000, 0)
		d.add("rule0", &got, now)
		for _, rr := range got.Answer {
			cttl := rr.Header().Ttl
			if cttl > domClientTTL || cttl > ttl {
				t.Fatalf("upstream ttl %d: client ttl %d (cap %d)", ttl, cttl, domClientTTL)
			}
			var a netip.Addr
			switch v := rr.(type) {
			case *dns.A:
				a, _ = netip.AddrFromSlice(v.A.To4())
			case *dns.AAAA:
				a, _ = netip.AddrFromSlice(v.AAAA)
			default:
				continue
			}
			// the last moment the app may still use its cached answer
			last := now.Add(time.Duration(cttl) * time.Second)
			if !d.has("rule0", a, last) {
				t.Fatalf("upstream ttl %d: entry for %v gone before the client ttl %d ran out", ttl, a, cttl)
			}
		}
	}
}
