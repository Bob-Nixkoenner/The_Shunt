package defense

import (
	"encoding/binary"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Names of sources, learned silently. Nothing is sent to learn them: the
// names come from packets that other devices send on the local segment
// anyway (DHCP requests with option 12, mDNS and LLMNR announcements).
//
// SECURITY: a host name is chosen by the device that sends it, so an attacker
// can set any text. It is untrusted input: cut short, printable characters
// only, kept in memory only, shown by the UI as plain text and marked
// "name given by the device, not verified". It is never used to decide
// anything (no block, no allow, no ignore).

// Limits of the name cache.
const (
	MaxNameLen    = 63 // a DNS label
	maxNameCache  = 512
	nameTTL       = 24 * time.Hour
	maxNamesInPkt = 16 // records looked at per packet
)

// Where a name came from. Names a device announces about itself (mDNS,
// LLMNR; the address in the record equals the packet's source) rank above
// names read from a DHCP request.
const (
	NameDHCP  = "dhcp"
	NameMDNS  = "mdns"
	NameLLMNR = "llmnr"
)

// SrcName is the name of one source as the API shows it.
type SrcName struct {
	Name   string `json:"name"`
	Source string `json:"source"` // dhcp, mdns or llmnr
}

type nameRec struct {
	SrcName
	at time.Time
}

// NameCache keeps the learned names, in memory only.
type NameCache struct {
	mu  sync.Mutex
	m   map[netip.Addr]nameRec
	now func() time.Time
}

// NewNameCache returns an empty cache.
func NewNameCache() *NameCache { return &NameCache{m: map[netip.Addr]nameRec{}, now: time.Now} }

func nameRank(source string) int {
	if source == NameDHCP {
		return 1
	}
	return 2
}

// Set remembers name for a. The name is cleaned; an empty result is not
// stored. A fresh name from a better source is not replaced by a worse one.
func (c *NameCache) Set(a netip.Addr, name, source string) {
	a = a.Unmap()
	name = CleanText(name, MaxNameLen)
	if !a.IsValid() || name == "" || a.IsUnspecified() || a.IsMulticast() {
		return
	}
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if old, ok := c.m[a]; ok && now.Sub(old.at) < nameTTL && nameRank(old.Source) > nameRank(source) {
		return
	}
	if _, ok := c.m[a]; !ok && len(c.m) >= maxNameCache {
		c.evictLocked(now)
		if len(c.m) >= maxNameCache {
			return // full of fresh names: the newcomer waits
		}
	}
	c.m[a] = nameRec{SrcName{name, source}, now}
}

// evictLocked drops expired names, and the oldest one when none expired.
func (c *NameCache) evictLocked(now time.Time) {
	var oldest netip.Addr
	var ot time.Time
	for a, r := range c.m {
		if now.Sub(r.at) >= nameTTL {
			delete(c.m, a)
			continue
		}
		if ot.IsZero() || r.at.Before(ot) {
			oldest, ot = a, r.at
		}
	}
	if len(c.m) >= maxNameCache && oldest.IsValid() {
		delete(c.m, oldest)
	}
}

// Get returns the name of a, if one is known and not expired.
func (c *NameCache) Get(a netip.Addr) (SrcName, bool) {
	a = a.Unmap()
	c.mu.Lock()
	defer c.mu.Unlock()
	r, ok := c.m[a]
	if !ok || c.now().Sub(r.at) >= nameTTL {
		delete(c.m, a)
		return SrcName{}, false
	}
	return r.SrcName, true
}

// For returns the names of the given source addresses (text form) that are
// known; nil when there is none.
func (c *NameCache) For(srcs []string) map[string]SrcName {
	var out map[string]SrcName
	for _, s := range srcs {
		a, err := netip.ParseAddr(s)
		if err != nil {
			continue
		}
		if n, ok := c.Get(a); ok {
			if out == nil {
				out = map[string]SrcName{}
			}
			out[a.Unmap().String()] = n
		}
	}
	return out
}

// Len is the number of names kept.
func (c *NameCache) Len() int { c.mu.Lock(); defer c.mu.Unlock(); return len(c.m) }

// Forget drops every name (new network).
func (c *NameCache) Forget() { c.mu.Lock(); c.m = map[netip.Addr]nameRec{}; c.mu.Unlock() }

// NameClaim is one name found in a packet.
type NameClaim struct {
	Addr   netip.Addr
	Name   string
	Source string
}

// ParseDHCPClientName reads the host name (option 12) from a DHCP packet
// (UDP payload) sent by a client (op 1: DISCOVER, REQUEST, INFORM). srcIP is
// the IP source of the packet (0.0.0.0 before the client has an address). The
// address the name belongs to is ciaddr, else the requested address (option
// 50), else srcIP when it is a real address. Malformed packets give ok=false.
func ParseDHCPClientName(p []byte, srcIP netip.Addr) (c NameClaim, ok bool) {
	const opts = 240
	if len(p) < opts+3 || p[0] != 1 || p[236] != 0x63 || p[237] != 0x82 || p[238] != 0x53 || p[239] != 0x63 {
		return c, false
	}
	var name string
	var req netip.Addr
	for i, n := opts, 0; i < len(p) && n < maxDHCPOptions; n++ {
		code := p[i]
		if code == 255 {
			break
		}
		if code == 0 {
			i++
			continue
		}
		if i+1 >= len(p) || i+2+int(p[i+1]) > len(p) {
			break
		}
		l := int(p[i+1])
		v := p[i+2 : i+2+l]
		switch code {
		case 12:
			name = CleanText(string(v), MaxNameLen)
		case 50:
			if l == 4 {
				req = netip.AddrFrom4([4]byte(v))
			}
		}
		i += 2 + l
	}
	if name == "" {
		return c, false
	}
	addr := netip.AddrFrom4([4]byte(p[12:16])) // ciaddr
	if addr.IsUnspecified() {
		addr = req
	}
	if !addr.IsValid() || addr.IsUnspecified() {
		addr = srcIP.Unmap()
	}
	if !addr.IsValid() || addr.IsUnspecified() || addr.IsMulticast() {
		return c, false
	}
	return NameClaim{addr, name, NameDHCP}, true
}

// ParseMDNSNames reads the names a device announces about itself from an
// mDNS (port 5353) or LLMNR (port 5355) message (UDP payload). Only address
// records (A, AAAA) whose address equals srcIP count: a device may name
// itself, but not another device. mDNS names must end in ".local"; the
// suffix is cut. LLMNR names are single labels. Everything else is ignored.
func ParseMDNSNames(p []byte, srcIP netip.Addr, llmnr bool) []NameClaim {
	srcIP = srcIP.Unmap()
	if len(p) < 12 || len(p) > 9000 || !srcIP.IsValid() {
		return nil
	}
	var msg dns.Msg
	if msg.Unpack(p) != nil || !msg.Response {
		return nil
	}
	rrs := append(append([]dns.RR{}, msg.Answer...), msg.Extra...)
	var out []NameClaim
	for i, rr := range rrs {
		if i >= maxNamesInPkt {
			break
		}
		var ip netip.Addr
		switch r := rr.(type) {
		case *dns.A:
			ip, _ = netip.AddrFromSlice(r.A)
		case *dns.AAAA:
			ip, _ = netip.AddrFromSlice(r.AAAA)
		default:
			continue
		}
		if ip.Unmap() != srcIP {
			continue
		}
		name := strings.TrimSuffix(strings.ToLower(rr.Header().Name), ".")
		src := NameLLMNR
		if !llmnr {
			var ok bool
			if name, ok = strings.CutSuffix(name, ".local"); !ok {
				continue
			}
			src = NameMDNS
		}
		if name == "" || strings.Contains(name, ".") {
			continue // only the host's own label
		}
		if name = CleanText(name, MaxNameLen); name != "" {
			out = append(out, NameClaim{srcIP, name, src})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// NamesFromIPv4 reads the names out of one IPv4 packet (from the IP header
// on) as an AF_PACKET socket hands it over: DHCP from a client (UDP 68 -> 67),
// mDNS (UDP 5353) and LLMNR (UDP 5355). Anything else, fragments and short
// packets give nil. Pure function: the sensor only feeds it.
func NamesFromIPv4(pkt []byte) []NameClaim {
	if len(pkt) < 28 || pkt[0]>>4 != 4 || pkt[9] != 17 || binary.BigEndian.Uint16(pkt[6:8])&0x3fff != 0 {
		return nil
	}
	ihl := int(pkt[0]&0xf) * 4
	if ihl < 20 || len(pkt) < ihl+8 {
		return nil
	}
	src := netip.AddrFrom4([4]byte(pkt[12:16]))
	sp, dp := binary.BigEndian.Uint16(pkt[ihl:]), binary.BigEndian.Uint16(pkt[ihl+2:])
	ulen := int(binary.BigEndian.Uint16(pkt[ihl+4:]))
	end := len(pkt)
	if ulen >= 8 && ihl+ulen < end {
		end = ihl + ulen
	}
	pl := pkt[ihl+8 : end]
	switch {
	case sp == 68 && dp == 67:
		if c, ok := ParseDHCPClientName(pl, src); ok {
			return []NameClaim{c}
		}
	case dp == 5353 || sp == 5353:
		return ParseMDNSNames(pl, src, false)
	case dp == 5355 || sp == 5355:
		return ParseMDNSNames(pl, src, true)
	}
	return nil
}

// Names gives access to the cache of learned source names.
func (m *Manager) Names() *NameCache { return m.names }

// LearnNames stores claims found in packets. This machine's own addresses
// are skipped.
func (m *Manager) LearnNames(cl []NameClaim) {
	for _, c := range cl {
		if m.ownAddr != nil && m.ownAddr(c.Addr) {
			continue
		}
		m.names.Set(c.Addr, c.Name, c.Source)
	}
}

func eventSrcs(evs []Event) []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range evs {
		if e.Src != "" && !seen[e.Src] {
			seen[e.Src] = true
			out = append(out, e.Src)
		}
	}
	return out
}

// Snapshot returns address -> name of every fresh entry (for the evidence
// export, which keeps only the sources it needs).
func (c *NameCache) Snapshot() map[string]string {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	out := make(map[string]string, len(c.m))
	for a, r := range c.m {
		if now.Sub(r.at) < nameTTL {
			out[a.String()] = r.Name
		}
	}
	return out
}
