package defense

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

// v6 builds an IPv6 packet from src with the given next header and payload.
func v6(src [16]byte, hop, next byte, payload []byte) []byte {
	p := make([]byte, 40, 40+len(payload))
	p[0], p[6], p[7] = 0x60, next, hop
	binary.BigEndian.PutUint16(p[4:], uint16(len(payload)))
	copy(p[8:], src[:])
	p[24], p[39] = 0xff, 1 // ff02::1 (all nodes)
	return append(p, payload...)
}

func ll(last byte) [16]byte { return [16]byte{0xfe, 0x80, 15: last} }

func raBody(lifetime uint16, opts ...[]byte) []byte {
	b := make([]byte, 16)
	b[0] = 134
	binary.BigEndian.PutUint16(b[6:], lifetime)
	for _, o := range opts {
		b = append(b, o...)
	}
	return b
}

func prefixOpt(valid uint32) []byte {
	o := make([]byte, 32)
	o[0], o[1], o[2], o[3] = 3, 4, 64, 0xc0
	binary.BigEndian.PutUint32(o[4:], valid)
	copy(o[16:], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 1}) // 2001:db8:1::/64
	return o
}

func rdnssOpt(life uint32, last byte) []byte {
	o := make([]byte, 24)
	o[0], o[1] = 25, 3
	binary.BigEndian.PutUint32(o[4:], life)
	copy(o[8:], []byte{0x20, 0x01, 0x0d, 0xb8})
	o[23] = last
	return o
}

func slla(m byte) []byte { return []byte{1, 1, 2, 0, 0, 0, 0, m} }

func TestParseRA(t *testing.T) {
	p := v6(ll(1), 255, 58, raBody(1800, slla(1), prefixOpt(86400), rdnssOpt(600, 53)))
	ra, ok := ParseRA(p, "")
	if !ok || ra.RouterLifetime != 1800 || len(ra.Prefixes) != 1 || ra.Prefixes[0].Prefix.String() != "2001:db8:1::/64" ||
		len(ra.RDNSS) != 1 || ra.MAC != "02:00:00:00:00:01" || ra.RDNSSLifetime != 600 {
		t.Fatalf("%+v %v", ra, ok)
	}
	if _, ok := ParseRA(v6(ll(1), 64, 58, raBody(1800)), ""); ok {
		t.Fatal("hop limit must be 255")
	}
	g := ll(1)
	g[0], g[1] = 0x20, 0x01
	if _, ok := ParseRA(v6(g, 255, 58, raBody(1800)), ""); ok {
		t.Fatal("source must be link-local")
	}
	if _, ok := ParseRA(v6(ll(1), 255, 58, []byte{133, 0, 0, 0, 0, 0, 0, 0}), ""); ok {
		t.Fatal("RS is no RA")
	}
	// length-0 option stops parsing without a panic
	if _, ok := ParseRA(v6(ll(1), 255, 58, append(raBody(1), 3, 0, 0, 0, 0, 0, 0, 0)), ""); !ok {
		t.Fatal("still an RA")
	}
}

func TestParseRAFragment(t *testing.T) {
	frag := append([]byte{58, 0, 0, 0, 0, 0, 0, 1}, raBody(1800)...)
	ra, ok := ParseRA(v6(ll(1), 255, 44, frag), "")
	if !ok || !ra.Fragmented {
		t.Fatalf("%+v %v", ra, ok)
	}
	frag[2] = 0x00
	frag[3] = 0x08 // offset 1: not the first fragment
	if _, ok := ParseRA(v6(ll(1), 255, 44, frag), ""); ok {
		t.Fatal("later fragment")
	}
}

func TestRAWatch(t *testing.T) {
	now := time.Unix(1000, 0)
	w := newRAWatch()
	w.now = func() time.Time { return now }
	feed := func(src byte, mac string, life uint16, opts ...[]byte) []Event {
		ra, ok := ParseRA(v6(ll(src), 255, 58, raBody(life, opts...)), mac)
		if !ok {
			t.Fatal("parse")
		}
		return w.Feed(ra)
	}
	if e := feed(1, "02:00:00:00:00:01", 1800, prefixOpt(86400), rdnssOpt(600, 53)); len(e) != 0 {
		t.Fatalf("first router is the baseline: %+v", e)
	}
	if e := feed(1, "02:00:00:00:00:01", 1800, prefixOpt(86400), rdnssOpt(600, 53)); len(e) != 0 {
		t.Fatalf("repeat: %+v", e)
	}
	e := feed(2, "02:00:00:00:00:02", 1800, rdnssOpt(600, 66))
	if len(e) != 2 || e[0].Severity != SevHigh || e[0].Kind != KindRogueRA || !strings.Contains(e[0].Detail, "second router") {
		t.Fatalf("second router with DNS: %+v", e)
	}
	if e := feed(2, "02:00:00:00:00:02", 1800, rdnssOpt(600, 66)); len(e) != 0 {
		t.Fatalf("once: %+v", e)
	}
	if e := feed(1, "02:00:00:00:00:77", 1800); len(e) != 1 || e[0].Severity != SevHigh {
		t.Fatalf("mac change: %+v", e)
	}
	if e := feed(1, "02:00:00:00:00:77", 0); len(e) != 1 || !strings.Contains(e[0].Detail, "lifetime 0") {
		t.Fatalf("router lifetime 0: %+v", e)
	}
	if e := feed(1, "02:00:00:00:00:77", 0, prefixOpt(0)); len(e) != 1 || !strings.Contains(e[0].Detail, "valid lifetime 0") {
		t.Fatalf("prefix lifetime 0: %+v", e)
	}
	if e := feed(1, "02:00:00:00:00:77", 0, rdnssOpt(0, 53)); len(e) != 1 || !strings.Contains(e[0].Detail, "lifetime 0 (removes them)") {
		t.Fatalf("rdnss lifetime 0: %+v", e)
	}
}

func TestRAFlood(t *testing.T) {
	now := time.Unix(1000, 0)
	w := newRAWatch()
	w.now = func() time.Time { return now }
	ra, _ := ParseRA(v6(ll(1), 255, 58, raBody(0)), "")
	var got int
	for i := 0; i < 3*raFloodN; i++ {
		got += len(w.Feed(ra))
	}
	if got != 1 {
		t.Fatalf("flood events: %d", got)
	}
}

func dhcp6(src [16]byte, typ byte, duid ...byte) []byte {
	m := []byte{typ, 0, 0, 1, 0, 2, 0, byte(len(duid))}
	m = append(m, duid...)
	u := make([]byte, 8, 8+len(m))
	binary.BigEndian.PutUint16(u, 547)
	binary.BigEndian.PutUint16(u[2:], 546)
	binary.BigEndian.PutUint16(u[4:], uint16(8+len(m)))
	return v6(src, 64, 17, append(u, m...))
}

func TestDHCPv6TwoServers(t *testing.T) {
	w := newRAWatch()
	a, ok := ParseDHCPv6(dhcp6(ll(1), 2, 0, 1, 2, 3))
	if !ok || a.DUID != "00010203" {
		t.Fatalf("%+v %v", a, ok)
	}
	if e := w.FeedDHCPv6(a); len(e) != 0 {
		t.Fatal("one server")
	}
	b, _ := ParseDHCPv6(dhcp6(ll(2), 2, 9, 9, 9, 9))
	e := w.FeedDHCPv6(b)
	if len(e) != 1 || e[0].Kind != KindRogueRA || e[0].Severity != SevHigh {
		t.Fatalf("%+v", e)
	}
	if len(w.FeedDHCPv6(b)) != 0 {
		t.Fatal("once")
	}
	if _, ok := ParseDHCPv6(dhcp6(ll(1), 1, 1)); ok {
		t.Fatal("solicit is not a server message")
	}
}

func FuzzParseRA(f *testing.F) {
	f.Add(v6(ll(1), 255, 58, raBody(1800, prefixOpt(1), rdnssOpt(1, 1))))
	f.Add(dhcp6(ll(1), 2, 1, 2))
	f.Fuzz(func(t *testing.T, b []byte) { ParseRA(b, ""); ParseDHCPv6(b) })
}
