package defense

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

func udp6(src string, sp, dp uint16, pl []byte) []byte {
	p := make([]byte, 48, 48+len(pl))
	p[0] = 0x60
	binary.BigEndian.PutUint16(p[4:], uint16(8+len(pl)))
	p[6], p[7] = 17, 255
	copy(p[8:], net.ParseIP(src).To16())
	copy(p[24:], net.ParseIP("ff02::fb").To16())
	binary.BigEndian.PutUint16(p[40:], sp)
	binary.BigEndian.PutUint16(p[42:], dp)
	binary.BigEndian.PutUint16(p[44:], uint16(8+len(pl)))
	return append(p, pl...)
}

func TestNamesFromIPv6(t *testing.T) {
	m := new(dns.Msg)
	m.Response = true
	m.Answer = []dns.RR{&dns.AAAA{Hdr: dns.RR_Header{Name: "speaker.local.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 120}, AAAA: net.ParseIP("fe80::1234")}}
	b, _ := m.Pack()
	pkt := udp6("fe80::1234", 5353, 5353, b)
	if c := NamesFromIPv6(pkt); len(c) != 1 || c[0].Name != "speaker" || c[0].Addr != netip.MustParseAddr("fe80::1234") || c[0].Source != NameMDNS {
		t.Fatalf("%+v", c)
	}
	// a record about another address is a forged claim
	if c := NamesFromIPv6(udp6("fe80::9999", 5353, 5353, b)); len(c) != 0 {
		t.Fatalf("foreign claim accepted: %+v", c)
	}
	tcp := append([]byte{}, pkt...)
	tcp[6] = 6
	if NamesFromIPv6(tcp) != nil || NamesFromIPv6(pkt[:47]) != nil || NamesFromIPv6(nil) != nil {
		t.Fatal("non-UDP or short packet accepted")
	}
}
