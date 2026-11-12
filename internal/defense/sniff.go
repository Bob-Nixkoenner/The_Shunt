package defense

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Env describes the network the sensors watch. All fields are optional.
// It never leaves the machine and is never logged.
type Env struct {
	Iface      string
	SSID       string
	GatewayIP  string
	GatewayMAC string
	DNS        []string // resolvers the network handed out
	// DHCPProbe: the active DHCP DISCOVER probe may be sent (see ProbeAllowed).
	DHCPProbe bool
	// DNSProbe: the active DNS comparison may query resolvers directly.
	DNSProbe bool
}

// gwWatch notices a new MAC for the gateway address (ARP or NDP spoofing).
type gwWatch struct {
	mu   sync.Mutex
	ip   netip.Addr
	mac  string
	said bool
}

func newGWWatch(ip, mac string) *gwWatch {
	a, _ := netip.ParseAddr(ip)
	return &gwWatch{ip: a, mac: strings.ToLower(mac)}
}

// Feed takes one neighbour table entry and returns an event when the
// gateway's MAC changed. The first MAC seen becomes the baseline when none
// was known. The event is returned once per new MAC.
func (g *gwWatch) Feed(ip netip.Addr, mac string) (Event, bool) {
	mac = strings.ToLower(mac)
	if !g.ip.IsValid() || ip.Unmap() != g.ip.Unmap() || mac == "" || mac == "00:00:00:00:00:00" {
		return Event{}, false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.mac == "" {
		g.mac = mac
		return Event{}, false
	}
	if mac == g.mac {
		g.said = false
		return Event{}, false
	}
	if g.said {
		return Event{}, false
	}
	g.said = true
	return Event{Kind: KindARP, Severity: SevHigh, Detail: "the gateway's hardware address changed (possible ARP/NDP spoofing)"}, true
}

// dhcpLearnWindow is how long after joining the first answering server may
// be learned as the network's own DHCP server.
const dhcpLearnWindow = 10 * time.Second

// dhcpWatch notices a second DHCP server answering. Known servers are the
// gateway address, the server of this client's own lease (when readable)
// and the first server that answers within the learning window while
// nothing else known has answered. Only another server than these is
// reported. Without any confirmed server (no lease, nobody known answered)
// an unknown server only produces an info observation and is learned.
type dhcpWatch struct {
	mu        sync.Mutex
	known     map[netip.Addr]bool
	start     time.Time
	now       func() time.Time
	hasLease  bool
	confirmed bool // a known server (or a learned one) has answered
	said      bool
}

func newDHCPWatch() *dhcpWatch { return newDHCPWatchWith("", nil, time.Now) }

// newDHCPWatchFor starts with the gateway address as known server.
func newDHCPWatchFor(gateway string) *dhcpWatch { return newDHCPWatchWith(gateway, nil, time.Now) }

// newDHCPWatchWith also takes the server addresses of the client's own
// lease and a clock (the learning window starts now).
func newDHCPWatchWith(gateway string, lease []netip.Addr, now func() time.Time) *dhcpWatch {
	d := &dhcpWatch{known: map[netip.Addr]bool{}, now: now, start: now()}
	if a, err := netip.ParseAddr(gateway); err == nil {
		d.known[a.Unmap()] = true
	}
	for _, a := range lease {
		if a.IsValid() {
			d.known[a.Unmap()] = true
			d.hasLease = true
			d.confirmed = true
		}
	}
	return d
}

// Feed takes the server address of one OFFER/ACK.
func (d *dhcpWatch) Feed(server netip.Addr) (Event, bool) {
	server = server.Unmap()
	if !server.IsValid() {
		return Event{}, false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.known[server] {
		d.confirmed = true
		return Event{}, false
	}
	inWindow := d.now().Sub(d.start) < dhcpLearnWindow
	if inWindow && !d.hasLease && !d.confirmed {
		// first answer after joining: this is the network's server
		d.known[server] = true
		d.confirmed = true
		return Event{}, false
	}
	if !d.confirmed {
		// no basis to compare with: note it, do not alarm
		d.known[server] = true
		d.confirmed = true
		return Event{Kind: KindObservation, Severity: SevInfo, Src: server.String(), Proto: "udp", Port: 67,
			Detail: "DHCP server learned late, no baseline to compare (no alarm)"}, true
	}
	if d.said {
		return Event{}, false
	}
	d.said = true
	return Event{Kind: KindRogueDHCP, Severity: SevHigh, Src: server.String(), Proto: "udp", Port: 67,
		Detail: "a second DHCP server answered on this network (second server)"}, true
}

// ParseDHCPReply extracts the server address of a DHCP OFFER or ACK from a
// UDP payload (BOOTP header + options). It returns ok=false for anything
// else, including malformed packets.
func ParseDHCPReply(p []byte) (server netip.Addr, ok bool) {
	// op(1) htype hlen hops xid(4) secs flags ciaddr yiaddr siaddr giaddr chaddr(16) sname(64) file(128) cookie(4)
	const opts = 240
	if len(p) < opts+3 || p[0] != 2 || p[236] != 0x63 || p[237] != 0x82 || p[238] != 0x53 || p[239] != 0x63 {
		return netip.Addr{}, false
	}
	var id netip.Addr
	var typ byte
	for i := opts; i < len(p); {
		c := p[i]
		if c == 255 {
			break
		}
		if c == 0 {
			i++
			continue
		}
		if i+1 >= len(p) || i+2+int(p[i+1]) > len(p) {
			return netip.Addr{}, false
		}
		l := int(p[i+1])
		v := p[i+2 : i+2+l]
		switch c {
		case 53:
			if l == 1 {
				typ = v[0]
			}
		case 54:
			if l == 4 {
				id, _ = netip.AddrFromSlice(v)
			}
		}
		i += 2 + l
	}
	if (typ != 2 && typ != 5) || !id.IsValid() { // OFFER, ACK
		return netip.Addr{}, false
	}
	return id, true
}

// BuildDHCPDiscover returns a BOOTP/DHCP DISCOVER payload with the broadcast
// flag set (so every server's OFFER is a broadcast the passive listener
// sees), a random-looking client hardware address (chaddr), and only the
// message-type and parameter-request options: no host name, no vendor class.
func BuildDHCPDiscover(xid uint32, chaddr [6]byte) []byte {
	p := make([]byte, 240, 260)
	p[0], p[1], p[2] = 1, 1, 6 // BOOTREQUEST, Ethernet, hlen 6
	binary.BigEndian.PutUint32(p[4:], xid)
	p[10] = 0x80 // broadcast flag
	copy(p[28:], chaddr[:])
	p[236], p[237], p[238], p[239] = 0x63, 0x82, 0x53, 0x63
	return append(p, 53, 1, 1, 55, 3, 1, 3, 6, 255)
}

func ipChecksum(h []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(h); i += 2 {
		sum += uint32(h[i])<<8 | uint32(h[i+1])
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// BuildDHCPIPv4 wraps a DHCP payload in an IPv4+UDP header (0.0.0.0:68 ->
// 255.255.255.255:67, UDP checksum 0 = none) for a SOCK_DGRAM packet socket.
func BuildDHCPIPv4(payload []byte) []byte {
	n := 28 + len(payload)
	b := make([]byte, n)
	b[0], b[8], b[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(b[2:], uint16(n))
	copy(b[16:20], []byte{255, 255, 255, 255})
	binary.BigEndian.PutUint16(b[10:], ipChecksum(b[:20]))
	binary.BigEndian.PutUint16(b[20:], 68)
	binary.BigEndian.PutUint16(b[22:], 67)
	binary.BigEndian.PutUint16(b[24:], uint16(8+len(payload)))
	copy(b[28:], payload)
	return b
}

// dnsOnce lets a repeated check report a finding once until it comes back clean.
type dnsOnce struct {
	mu   sync.Mutex
	said map[string]bool
}

// Filter returns the events not reported since the last clean run and
// forgets findings that are gone.
func (d *dnsOnce) Filter(evs []Event) []Event {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := map[string]bool{}
	var out []Event
	for _, e := range evs {
		now[e.Detail] = true
		if !d.said[e.Detail] {
			out = append(out, e)
		}
	}
	d.said = now
	return out
}

// DNSCheck compares what the network's resolvers say with a reference
// (resolved over the default route, ideally through a tunnel). The names
// are ones whose address never changes. Only the questions to the network's
// own resolvers travel over the local network.
type DNSCheck struct {
	// Reference resolves name over a path the local network does not
	// control; nil disables the check.
	Reference func(ctx context.Context, name string) ([]netip.Addr, error)
	// Dial opens the UDP query socket for the network's own resolvers
	// (SO_MARK / interface set by the Linux side); nil = net.Dialer.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// Names to ask; default pairs below.
	Names []string
	// Public is a resolver of our own choice (default 9.9.9.9:53). It is
	// asked only through PublicDial.
	Public string
	// PublicDial opens the socket for the question to Public. It must lead
	// through the default route's tunnel and nowhere else: a question to a
	// resolver the network did not name, sent over the local network, shows
	// that network a destination and names it would not see otherwise (lab
	// Q01/R03/R04, 2026-11-11). nil = Public is not asked (no tunnel is the
	// default route). The answer is a second reference next to Reference
	// and shows whether port 53 inside the tunnel is answered truthfully.
	PublicDial func(ctx context.Context, network, addr string) (net.Conn, error)
	// RefTimeout bounds one Reference call (default dnsRefTimeout).
	RefTimeout time.Duration
}

// Fixed names with stable addresses.
var defaultDNSNames = []string{"dns.google", "one.one.one.one"}

func (c *DNSCheck) ask(ctx context.Context, dial func(ctx context.Context, network, addr string) (net.Conn, error), server, name string) ([]netip.Addr, error) {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), dns.TypeA)
	cl := &dns.Client{Net: "udp", Timeout: 3 * time.Second, Dialer: nil}
	var conn net.Conn
	var err error
	if dial != nil {
		conn, err = dial(ctx, "udp", server)
	} else {
		var d net.Dialer
		conn, err = d.DialContext(ctx, "udp", server)
	}
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	r, _, err := cl.ExchangeWithConnContext(ctx, q, &dns.Conn{Conn: conn})
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, rr := range r.Answer {
		if a, ok := rr.(*dns.A); ok {
			if ip, ok := netip.AddrFromSlice(a.A); ok {
				out = append(out, ip.Unmap())
			}
		}
	}
	return out, nil
}

func overlap(a, b []netip.Addr) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}

// Run asks the question and returns one event per finding. Resolvers that
// do not answer produce no event (no answer is not an attack).
func (c *DNSCheck) Run(ctx context.Context, env Env) []Event {
	evs, _ := c.RunStatus(ctx, env)
	return evs
}

// reservedNets are ranges a fixed public name is never answered with, next
// to private, loopback and link-local addresses: the benchmark range (a
// typical rebind / sinkhole target). The documentation ranges are left out
// on purpose: the tests use them as stand-ins for public addresses.
var reservedNets = []netip.Prefix{
	netip.MustParsePrefix("198.18.0.0/15"),
}

// reservedAnswer reports an address that a fixed public name never has.
func reservedAnswer(a netip.Addr) bool {
	a = a.Unmap()
	if a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsUnspecified() {
		return true
	}
	for _, p := range reservedNets {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func anyReserved(as []netip.Addr) bool {
	for _, a := range as {
		if reservedAnswer(a) {
			return true
		}
	}
	return false
}

// knownDNSAnswers are the addresses of the default names, published by
// their operators and unchanged for years. They stand in when the reference
// cannot be reached (for example because whoever redirects DNS also cuts
// the tunnel); a finding that rests on them alone is rated one step lower.
var knownDNSAnswers = map[string][]netip.Addr{
	"dns.google":      {netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("8.8.4.4")},
	"one.one.one.one": {netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("1.0.0.1")},
}

// dnsRefTimeout bounds one reference lookup, so a dead path to the
// reference cannot use up the time of the whole check.
const dnsRefTimeout = 8 * time.Second

// RunStatus is Run plus refOK: whether a reference answered for at least
// one name. A nil Reference never reports failure.
//
// Three steps, in this order:
//
//  1. The network's own resolvers, over the local network. These are the
//     only questions that network gets to see, and they go out first: a man
//     in the middle who redirects DNS often cuts or delays the tunnel as
//     well, and everything that needs the tunnel then waits. Asked first,
//     the reference held the whole check until the real path was back, so
//     the local questions never saw the redirection (lab R05, 2026-11-11).
//  2. The public resolver, through the tunnel (PublicDial). With the tunnel
//     down the kill switch keeps the question on this machine; after the
//     first question without an answer the others are not sent.
//  3. The reference (DoH over the default route), with its own time limit.
//
// The local answers are compared with the reference; when it is out of
// reach, with the public resolver's answer from the tunnel; when the tunnel
// carries nothing, with the built-in addresses of the default names (rated
// one step lower). A reserved or private answer of a network resolver for a
// fixed public name counts without any reference (rebind pattern).
func (c *DNSCheck) RunStatus(ctx context.Context, env Env) (evs []Event, refOK bool) {
	names := c.Names
	if len(names) == 0 {
		names = defaultDNSNames
	}
	pub := c.Public
	if pub == "" {
		pub = "9.9.9.9:53"
	}
	type answers struct {
		local  [][]netip.Addr // one per resolver that answered
		public []netip.Addr
	}
	got := make([]answers, len(names))
	var rebind bool
	for i, name := range names {
		for _, s := range env.DNS {
			if _, _, err := net.SplitHostPort(s); err != nil {
				s = net.JoinHostPort(s, "53")
			}
			a, err := c.ask(ctx, c.Dial, s, name)
			if err != nil || len(a) == 0 {
				continue // no answer is not an attack
			}
			if anyReserved(a) {
				rebind = true
				continue
			}
			got[i].local = append(got[i].local, a)
		}
	}
	if c.PublicDial != nil {
		for i, name := range names {
			a, err := c.ask(ctx, c.PublicDial, pub, name)
			if err != nil {
				break // the tunnel carries nothing right now
			}
			// A reserved answer here says nothing about the local network
			// (a filtering resolver at the tunnel's far end): not used.
			if len(a) > 0 && !anyReserved(a) {
				got[i].public = a
			}
		}
	}
	var localDiff, tunnelDiff, builtinOnly bool
	for i, name := range names {
		var ref []netip.Addr
		builtin, doh := false, false
		if c.Reference != nil {
			rctx, cancel := context.WithTimeout(ctx, c.refTimeout())
			r, err := c.Reference(rctx, name)
			cancel()
			if err == nil && len(r) > 0 {
				ref, refOK, doh = r, true, true
			}
		}
		if len(ref) == 0 {
			if c.Reference == nil {
				continue // no reference configured: only the rebind pattern is judged
			}
			if ref = got[i].public; len(ref) > 0 {
				refOK = true // plain DNS through the tunnel stands in
			} else if ref = knownDNSAnswers[name]; len(ref) > 0 {
				builtin = true
			} else {
				continue // nothing to compare with
			}
		}
		for _, a := range got[i].local {
			if !overlap(a, ref) {
				localDiff = true
				builtinOnly = builtinOnly || builtin
			}
		}
		if a := got[i].public; doh && len(a) > 0 && !overlap(a, ref) {
			tunnelDiff = true
		}
	}
	sev, note := SevHigh, ""
	if builtinOnly {
		// the reference was out of reach: compared with the built-in addresses
		sev, note = SevMedium, " (reference not reachable, compared with the known addresses of the name)"
	}
	if localDiff {
		evs = append(evs, Event{Kind: KindDNSHijack, Severity: sev, Proto: "udp", Port: 53,
			Detail: "the network's resolver answers differently from the reference for a fixed name" + note})
	}
	if tunnelDiff {
		// Not the local network's doing (it only sees the tunnel), so one
		// step lower: the far end of the tunnel answers port 53 itself.
		evs = append(evs, Event{Kind: KindDNSHijack, Severity: SevMedium, Proto: "udp", Port: 53,
			Detail: "port 53 to a public resolver is answered with other data inside the tunnel (diverted at the tunnel's far end)"})
	}
	if rebind {
		evs = append(evs, Event{Kind: KindDNSHijack, Severity: SevHigh, Proto: "udp", Port: 53,
			Detail: "a fixed public name is answered with a private or reserved address (rebind pattern)"})
	}
	if c.Reference == nil {
		refOK = true
	}
	return evs, refOK
}

func (c *DNSCheck) refTimeout() time.Duration {
	if c.RefTimeout > 0 {
		return c.RefTimeout
	}
	return dnsRefTimeout
}

// dnsBackoff are the waits between attempts after a trigger when the
// reference could not be reached (about 50 s in all).
var dnsBackoff = []time.Duration{2 * time.Second, 5 * time.Second, 15 * time.Second, 30 * time.Second}

// DNSRetryNote is the observation reported when the reference stayed out of
// reach for a whole retry series.
const DNSRetryNote = "DNS reference not reachable, check not possible"

// dnsSeries runs the check until the reference answered or the backoff list
// is used up. A series is never cut short by new triggers (they only wait in
// the caller's channel). run reports findings and whether the reference
// answered; sleep returns false when ctx ended. The info observation is
// emitted once per failed series and not again until a series worked.
func dnsSeries(ctx context.Context, run func() ([]Event, bool), sleep func(context.Context, time.Duration) bool,
	emit func(Event), once *dnsOnce, noted *bool) {
	for i := 0; ; i++ {
		evs, ok := run()
		for _, ev := range once.Filter(evs) {
			emit(ev)
		}
		if ok {
			*noted = false
			return
		}
		if i >= len(dnsBackoff) {
			break
		}
		if !sleep(ctx, dnsBackoff[i]) {
			return
		}
	}
	if !*noted {
		*noted = true
		emit(Event{Kind: KindObservation, Severity: SevInfo, Proto: "udp", Port: 53, Detail: DNSRetryNote})
	}
}

// TwinStore remembers which gateway MACs belong to which Wi-Fi name, so a
// second access point with the same name but another gateway stands out.
// The file lives on this machine (mode 0600); names and addresses are
// stored hashed with a per-file salt and are never logged.
type TwinStore struct {
	Path string
	mu   sync.Mutex
	data twinFile
	load bool
}

type twinFile struct {
	Salt string              `json:"salt"`
	Nets map[string][]string `json:"nets"` // hash(ssid) -> hashes of gateway MACs
}

func (t *TwinStore) read() {
	if t.load {
		return
	}
	t.load = true
	t.data = twinFile{Nets: map[string][]string{}}
	if b, err := os.ReadFile(t.Path); err == nil {
		_ = json.Unmarshal(b, &t.data)
	}
	if t.data.Nets == nil {
		t.data.Nets = map[string][]string{}
	}
	if t.data.Salt == "" {
		s := sha256.Sum256([]byte(time.Now().String() + t.Path))
		t.data.Salt = hex.EncodeToString(s[:8])
	}
}

func (t *TwinStore) h(s string) string {
	x := sha256.Sum256([]byte(t.data.Salt + "|" + strings.ToLower(s)))
	return hex.EncodeToString(x[:8])
}

// Check records the pair and reports true when ssid is known but this
// gateway MAC is new (first sight of a name never alarms). Empty values
// are ignored.
func (t *TwinStore) Check(ssid, gwMAC string) (twin bool) {
	if ssid == "" || gwMAC == "" {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.read()
	k, m := t.h(ssid), t.h(gwMAC)
	known := t.data.Nets[k]
	for _, x := range known {
		if x == m {
			return false
		}
	}
	twin = len(known) > 0
	if len(known) < 16 {
		known = append(known, m)
		sort.Strings(known)
		t.data.Nets[k] = known
	}
	t.save()
	return twin
}

func (t *TwinStore) save() {
	if t.Path == "" {
		return
	}
	b, err := json.Marshal(t.data)
	if err != nil {
		return
	}
	if os.MkdirAll(filepath.Dir(t.Path), 0o700) != nil {
		return
	}
	tmp := t.Path + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, t.Path)
	}
}

// TwinEvent is the event for a twin.
func TwinEvent() Event {
	return Event{Kind: KindEvilTwin, Severity: SevMedium,
		Detail: "a known Wi-Fi name appears with a different gateway (possible evil twin)"}
}
