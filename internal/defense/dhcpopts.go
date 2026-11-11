package defense

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// DHCP option watch (the "TunnelVision" pattern, CVE-2024-3661): a DHCP
// server that sends option 121 (classless static routes, RFC 3442) with
// routes more specific than the default route (for example 0.0.0.0/1 plus
// 128.0.0.0/1) makes the client send traffic around a VPN tunnel. The
// routes are applied on the physical interface, so the tunnel stays "up".
// Option 249 is Microsoft's variant of 121 with the same encoding; that
// equal encoding is an assumption (the research notes mark 249 as not
// confirmed), so it is parsed the same way and reported as "249".
//
// SECURITY: ParseDHCPOptions reads bytes sent by any host on the local
// segment. It must never panic, never allocate without a bound and never
// trust a length byte (marked for review).

// DHCPRoute is one classless static route.
type DHCPRoute struct {
	Prefix  netip.Prefix
	Gateway netip.Addr // 0.0.0.0 = on-link
}

// DHCPInfo is what ParseDHCPOptions found in one OFFER/ACK.
type DHCPInfo struct {
	Server    netip.Addr
	Routes    []DHCPRoute // from option 121 and, if present, 249
	RouteOpt  int         // 121 or 249 (0 = none)
	Malformed bool        // a route option did not parse completely
	Routers   []netip.Addr
	DNS       []netip.Addr
	Domain    bool // option 15 present
	NTP       bool // option 42 present
	WPAD      bool // option 252 present
	Codes     []int
}

const (
	maxDHCPOptions = 128 // options looked at per packet
	maxDHCPRoutes  = 64
)

// parseClassless decodes RFC 3442 route descriptors: width (0..32), the
// significant octets of the destination, then a 4-octet router.
func parseClassless(v []byte) (routes []DHCPRoute, ok bool) {
	for i := 0; i < len(v); {
		w := int(v[i])
		if w > 32 {
			return routes, false
		}
		n := (w + 7) / 8
		if i+1+n+4 > len(v) {
			return routes, false
		}
		var d [4]byte
		copy(d[:], v[i+1:i+1+n])
		gw := netip.AddrFrom4([4]byte(v[i+1+n : i+5+n]))
		p := netip.PrefixFrom(netip.AddrFrom4(d), w).Masked()
		if len(routes) < maxDHCPRoutes {
			routes = append(routes, DHCPRoute{Prefix: p, Gateway: gw})
		}
		i += 1 + n + 4
	}
	return routes, true
}

func addrList(v []byte, max int) []netip.Addr {
	var out []netip.Addr
	for i := 0; i+4 <= len(v) && len(out) < max; i += 4 {
		out = append(out, netip.AddrFrom4([4]byte(v[i:i+4])))
	}
	return out
}

// ParseDHCPOptions parses the options of a DHCP OFFER or ACK (UDP payload).
// It returns ok=false for everything else and for malformed headers.
// Options that appear several times are concatenated (RFC 3396).
func ParseDHCPOptions(p []byte) (info DHCPInfo, ok bool) {
	const opts = 240
	if len(p) < opts+3 || p[0] != 2 || p[236] != 0x63 || p[237] != 0x82 || p[238] != 0x53 || p[239] != 0x63 {
		return info, false
	}
	var typ byte
	seen := map[int]bool{}
	raw := map[byte][]byte{}
	count := 0
	for i := opts; i < len(p) && count < maxDHCPOptions; count++ {
		c := p[i]
		if c == 255 {
			break
		}
		if c == 0 {
			i++
			continue
		}
		if i+1 >= len(p) || i+2+int(p[i+1]) > len(p) {
			info.Malformed = true
			break
		}
		l := int(p[i+1])
		v := p[i+2 : i+2+l]
		seen[int(c)] = true
		switch c {
		case 53:
			if l == 1 {
				typ = v[0]
			}
		case 54:
			if l == 4 {
				info.Server = netip.AddrFrom4([4]byte(v))
			}
		case 3, 6, 121, 249:
			if len(raw[c])+l <= 1024 {
				raw[c] = append(raw[c], v...)
			} else {
				info.Malformed = true
			}
		}
		i += 2 + l
	}
	if typ != 2 && typ != 5 { // OFFER, ACK
		return DHCPInfo{}, false
	}
	info.Routers = addrList(raw[3], 4)
	info.DNS = addrList(raw[6], 4)
	for _, c := range []byte{121, 249} {
		if v, has := raw[c]; has {
			rs, good := parseClassless(v)
			if !good {
				info.Malformed = true
			}
			info.Routes = append(info.Routes, rs...)
			if info.RouteOpt == 0 {
				info.RouteOpt = int(c)
			}
		}
	}
	info.Domain, info.NTP, info.WPAD = seen[15], seen[42], seen[252]
	for c := range seen {
		info.Codes = append(info.Codes, c)
	}
	sort.Ints(info.Codes)
	return info, true
}

// Covering reports whether the routes hide the default route: any prefix
// shorter than /8 other than a plain /0 (for example the 0.0.0.0/1 and
// 128.0.0.0/1 pair), or a /0 whose gateway is not one of the routers the
// same reply names in option 3. A /0 via the offered router is what many
// ordinary networks send and is not reported.
func (i DHCPInfo) Covering() (bool, string) {
	for _, r := range i.Routes {
		bits := r.Prefix.Bits()
		switch {
		case bits > 0 && bits < 8:
			return true, "prefix " + r.Prefix.String() + " is shorter than /8"
		case bits == 0:
			same := false
			for _, rt := range i.Routers {
				if rt == r.Gateway {
					same = true
				}
			}
			if !same && r.Gateway.IsValid() && !r.Gateway.IsUnspecified() {
				return true, "default route to a router other than option 3"
			}
		}
	}
	return false, ""
}

// summary is the detail text; it names option numbers and route prefixes,
// never gateway or resolver addresses.
func (i DHCPInfo) summary() string {
	var codes []string
	for _, c := range i.Codes {
		switch c {
		case 3, 6, 15, 33, 42, 121, 249, 252:
			codes = append(codes, strconv.Itoa(c))
		}
	}
	var rs []string
	for k, r := range i.Routes {
		if k >= 8 {
			rs = append(rs, "...")
			break
		}
		rs = append(rs, r.Prefix.String())
	}
	s := "opts=" + strings.Join(codes, ",")
	if len(rs) > 0 {
		s += " routes=" + strings.Join(rs, ",")
	}
	if i.RouteOpt != 0 {
		s += fmt.Sprintf(" routeopt=%d", i.RouteOpt)
	}
	if i.Malformed {
		s += " malformed"
	}
	return s
}

// dhcpOptWatch turns parsed replies into events: one info event per
// distinct option summary (so renewals stay quiet) and one high event for
// route options that cover the default route.
type dhcpOptWatch struct {
	mu   sync.Mutex
	seen map[string]bool
}

func newDHCPOptWatch() *dhcpOptWatch { return &dhcpOptWatch{seen: map[string]bool{}} }

// Feed returns the events for one reply.
func (w *dhcpOptWatch) Feed(i DHCPInfo) []Event {
	sum := i.summary()
	cover, why := i.Covering()
	key := sum
	if cover {
		key += "!"
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.seen[key] || len(w.seen) >= 32 {
		return nil
	}
	w.seen[key] = true
	ev := Event{Kind: KindDHCPOption, Severity: SevInfo, Proto: "udp", Port: 67, Detail: sum}
	if i.Server.IsValid() {
		ev.Src = i.Server.String()
	}
	if cover {
		ev.Severity = SevHigh
		ev.Detail = "covers-default " + sum + " (" + why + ")"
	} else if i.Malformed {
		ev.Severity = SevLow
	}
	return []Event{ev}
}
