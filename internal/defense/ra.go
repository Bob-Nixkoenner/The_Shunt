package defense

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// Rogue IPv6 router watch. It only observes: router advertisements
// (ICMPv6 type 134, RFC 4861) and DHCPv6 server replies, taken from a packet
// socket. RA-Guard (RFC 6105) is a switch feature, not a host switch, and
// RFC 7113 describes how extension headers and fragments get around it; the
// host can only watch (this file) or ignore RAs with the kernel's accept_ra
// setting. There is no kernel "ra_guard" switch.
//
// What counts as suspicious here is a heuristic: a second router, a router
// whose hardware address changed, RDNSS addresses that changed, and
// lifetime-0 messages that remove prefixes, DNS servers or the default
// router (the idea behind RFC 6104, assumption). Networks with two real
// routers will see the "second router" note; it is medium, not high.
//
// SECURITY: ParseRA, ParseDHCPv6 and ipv6Payload read bytes from any host on
// the segment: bounds checked, bounded output, no panics (marked for review).

// RA is the part of a router advertisement the watch needs.
type RA struct {
	Src            netip.Addr
	MAC            string // from the link layer or the source link-layer option
	RouterLifetime uint16
	Prefixes       []RAPrefix
	RDNSS          []netip.Addr
	RDNSSLifetime  uint32 // smallest lifetime seen in RDNSS options (0 = removal)
	HasRDNSS       bool
	Fragmented     bool // arrived behind a fragment header (evasion pattern, RFC 7113)
}

// RAPrefix is one prefix information option.
type RAPrefix struct {
	Prefix        netip.Prefix
	ValidLifetime uint32
}

const (
	maxRAOptions  = 32
	maxRAPrefixes = 8
	maxRDNSS      = 8
)

// ipv6Payload walks the IPv6 header and its extension headers and returns
// the upper protocol, its bytes and whether a fragment header (offset 0)
// was passed. Anything it cannot follow returns ok=false. Packet starts at
// the IPv6 header.
func ipv6Payload(p []byte) (src, dst netip.Addr, hop byte, proto byte, body []byte, frag bool, ok bool) {
	if len(p) < 40 || p[0]>>4 != 6 {
		return
	}
	src, _ = netip.AddrFromSlice(p[8:24])
	dst, _ = netip.AddrFromSlice(p[24:40])
	hop = p[7]
	proto = p[6]
	body = p[40:]
	for n := 0; n < 6; n++ {
		switch proto {
		case 0, 43, 60: // hop-by-hop, routing, destination options
			if len(body) < 8 {
				return
			}
			l := (int(body[1]) + 1) * 8
			if l > len(body) {
				return
			}
			proto, body = body[0], body[l:]
		case 44: // fragment: only the first fragment carries the ICMP header
			if len(body) < 8 || binary.BigEndian.Uint16(body[2:])&0xfff8 != 0 {
				return
			}
			frag = true
			proto, body = body[0], body[8:]
		default:
			ok = true
			return
		}
	}
	return
}

// ParseRA parses an IPv6 packet (from the IPv6 header on). It returns
// ok=false unless it is a valid router advertisement: ICMPv6 type 134 from
// a link-local source with hop limit 255 (RFC 4861 section 6.1.2).
func ParseRA(p []byte, mac string) (RA, bool) {
	src, _, hop, proto, body, frag, ok := ipv6Payload(p)
	if !ok || proto != 58 || hop != 255 || len(body) < 16 || body[0] != 134 || !src.IsLinkLocalUnicast() {
		return RA{}, false
	}
	ra := RA{Src: src, MAC: strings.ToLower(mac), RouterLifetime: binary.BigEndian.Uint16(body[6:]), Fragmented: frag}
	ra.RDNSSLifetime = ^uint32(0)
	o := body[16:]
	for n := 0; len(o) >= 2 && n < maxRAOptions; n++ {
		l := int(o[1]) * 8
		if l == 0 || l > len(o) {
			break // length 0 is invalid (RFC 4861); stop
		}
		v := o[:l]
		switch o[0] {
		case 1: // source link-layer address
			if l == 8 && ra.MAC == "" {
				ra.MAC = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", v[2], v[3], v[4], v[5], v[6], v[7])
			}
		case 3: // prefix information
			if l == 32 && len(ra.Prefixes) < maxRAPrefixes && v[2] <= 128 {
				a, _ := netip.AddrFromSlice(v[16:32])
				ra.Prefixes = append(ra.Prefixes, RAPrefix{netip.PrefixFrom(a, int(v[2])).Masked(), binary.BigEndian.Uint32(v[4:])})
			}
		case 25: // RDNSS (RFC 8106)
			if l >= 24 && (l-8)%16 == 0 {
				ra.HasRDNSS = true
				if lt := binary.BigEndian.Uint32(v[4:]); lt < ra.RDNSSLifetime {
					ra.RDNSSLifetime = lt
				}
				for i := 8; i+16 <= l && len(ra.RDNSS) < maxRDNSS; i += 16 {
					a, _ := netip.AddrFromSlice(v[i : i+16])
					ra.RDNSS = append(ra.RDNSS, a)
				}
			}
		}
		o = o[l:]
	}
	if !ra.HasRDNSS {
		ra.RDNSSLifetime = 0
	}
	sort.Slice(ra.RDNSS, func(i, j int) bool { return ra.RDNSS[i].Less(ra.RDNSS[j]) })
	return ra, true
}

// DHCPv6Reply is the server identity of an Advertise or Reply.
type DHCPv6Reply struct {
	Src  netip.Addr
	Type byte
	DUID string // hex of the server identifier option, "" if absent
}

// ParseDHCPv6 parses an IPv6 packet carrying UDP 547 -> 546 with a DHCPv6
// Advertise (2) or Reply (7).
func ParseDHCPv6(p []byte) (DHCPv6Reply, bool) {
	src, _, _, proto, body, _, ok := ipv6Payload(p)
	if !ok || proto != 17 || len(body) < 8+4 || binary.BigEndian.Uint16(body) != 547 || binary.BigEndian.Uint16(body[2:]) != 546 {
		return DHCPv6Reply{}, false
	}
	m := body[8:]
	if m[0] != 2 && m[0] != 7 {
		return DHCPv6Reply{}, false
	}
	r := DHCPv6Reply{Src: src, Type: m[0]}
	o := m[4:]
	for n := 0; len(o) >= 4 && n < 64; n++ {
		code, l := binary.BigEndian.Uint16(o), int(binary.BigEndian.Uint16(o[2:]))
		if 4+l > len(o) {
			break
		}
		if code == 2 && l > 0 && l <= 130 {
			r.DUID = fmt.Sprintf("%x", o[4:4+l])
		}
		o = o[4+l:]
	}
	return r, true
}

type raRouter struct {
	mac      string
	lifetime uint16
	last     time.Time
}

// raWatch holds what the network's routers said and decides what to report.
type raWatch struct {
	mu      sync.Mutex
	now     func() time.Time
	routers map[netip.Addr]*raRouter
	rdnss   string // baseline of the first RDNSS set seen
	said    map[string]bool
	flood   []time.Time
	v6      map[string]bool // DHCPv6 servers seen
}

func newRAWatch() *raWatch {
	return &raWatch{now: time.Now, routers: map[netip.Addr]*raRouter{}, said: map[string]bool{}, v6: map[string]bool{}}
}

const (
	raFloodN      = 60 // RAs in raFloodWindow
	raFloodWindow = 10 * time.Second
)

func (w *raWatch) once(key string) bool {
	if w.said[key] || len(w.said) > 64 {
		return false
	}
	w.said[key] = true
	return true
}

func raEvent(sev Severity, src netip.Addr, detail string) Event {
	return Event{Kind: KindRogueRA, Severity: sev, Src: src.String(), Proto: "icmpv6", Detail: detail}
}

// Feed takes one advertisement and returns the new findings. Each finding
// is reported once per router (and kind) until the watch restarts.
func (w *raWatch) Feed(ra RA) []Event {
	now := w.now()
	w.mu.Lock()
	defer w.mu.Unlock()
	var evs []Event
	// flood counter
	w.flood = append(w.flood, now)
	for len(w.flood) > 0 && now.Sub(w.flood[0]) > raFloodWindow {
		w.flood = w.flood[1:]
	}
	if len(w.flood) >= raFloodN && w.once("flood") {
		evs = append(evs, raEvent(SevMedium, ra.Src, fmt.Sprintf("flood: %d router advertisements in %ds", len(w.flood), int(raFloodWindow/time.Second))))
	}
	if len(w.flood) > 4*raFloodN {
		w.flood = w.flood[len(w.flood)-raFloodN:]
	}
	if ra.Fragmented && w.once("frag|"+ra.Src.String()) {
		evs = append(evs, raEvent(SevMedium, ra.Src, "advertisement behind a fragment header (pattern that evades switch RA-Guard, RFC 7113)"))
	}
	r := w.routers[ra.Src]
	if r == nil {
		if len(w.routers) >= 16 {
			return evs // enough routers tracked
		}
		w.routers[ra.Src] = &raRouter{mac: ra.MAC, lifetime: ra.RouterLifetime, last: now}
		if ra.RouterLifetime > 0 {
			if n := w.defaultRouters(); n >= 2 {
				sev, d := SevMedium, "a second router advertises itself as default router"
				if ra.HasRDNSS && ra.RDNSSLifetime > 0 {
					sev, d = SevHigh, "a second router advertises itself as default router and names DNS servers"
				}
				if w.once("second|" + ra.Src.String()) {
					evs = append(evs, raEvent(sev, ra.Src, d))
				}
			}
		}
	} else {
		if r.mac != "" && ra.MAC != "" && r.mac != ra.MAC && w.once("mac|"+ra.Src.String()+"|"+ra.MAC) {
			evs = append(evs, raEvent(SevHigh, ra.Src, "a router address is now advertised from another hardware address (possible spoofing)"))
		}
		if r.lifetime > 0 && ra.RouterLifetime == 0 && w.once("rl0|"+ra.Src.String()) {
			evs = append(evs, raEvent(SevMedium, ra.Src, "a default router announced lifetime 0 (withdraws the default route)"))
		}
		r.lifetime, r.last = ra.RouterLifetime, now
		if ra.MAC != "" {
			r.mac = ra.MAC
		}
	}
	for _, p := range ra.Prefixes {
		if p.ValidLifetime == 0 && w.once("pl0|"+ra.Src.String()+"|"+p.Prefix.String()) {
			evs = append(evs, raEvent(SevMedium, ra.Src, "a prefix was announced with valid lifetime 0 (removes addresses)"))
		}
	}
	if ra.HasRDNSS {
		if ra.RDNSSLifetime == 0 && w.once("dl0|"+ra.Src.String()) {
			evs = append(evs, raEvent(SevMedium, ra.Src, "DNS servers were announced with lifetime 0 (removes them)"))
		}
		var b strings.Builder
		for _, a := range ra.RDNSS {
			b.WriteString(a.String() + ",")
		}
		set := b.String()
		if w.rdnss == "" {
			w.rdnss = set
		} else if set != w.rdnss && ra.RDNSSLifetime > 0 && w.once("dns|"+set) {
			evs = append(evs, raEvent(SevMedium, ra.Src, "the announced DNS servers differ from those announced first"))
		}
	}
	return evs
}

func (w *raWatch) defaultRouters() int {
	n := 0
	for _, r := range w.routers {
		if r.lifetime > 0 {
			n++
		}
	}
	return n
}

// FeedDHCPv6 takes one Advertise/Reply and reports a second server.
func (w *raWatch) FeedDHCPv6(r DHCPv6Reply) []Event {
	id := r.DUID
	if id == "" {
		id = "ip:" + r.Src.String()
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.v6) < 16 {
		w.v6[id] = true
	}
	if len(w.v6) >= 2 && w.once("dhcpv6") {
		return []Event{{Kind: KindRogueRA, Severity: SevHigh, Src: r.Src.String(), Proto: "udp", Port: 547,
			Detail: "a second DHCPv6 server answered on this network"}}
	}
	return nil
}
