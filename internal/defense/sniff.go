package defense

import (
	"context"
	"crypto/sha256"
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

// dhcpWatch notices a second DHCP server answering.
type dhcpWatch struct {
	mu      sync.Mutex
	servers map[netip.Addr]bool
	said    bool
}

func newDHCPWatch() *dhcpWatch { return &dhcpWatch{servers: map[netip.Addr]bool{}} }

// Feed takes the server address of one OFFER/ACK.
func (d *dhcpWatch) Feed(server netip.Addr) (Event, bool) {
	server = server.Unmap()
	if !server.IsValid() {
		return Event{}, false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.servers[server] = true
	if len(d.servers) < 2 || d.said {
		return Event{}, false
	}
	d.said = true
	return Event{Kind: KindRogueDHCP, Severity: SevHigh, Src: server.String(), Proto: "udp", Port: 67,
		Detail: "a second DHCP server answered on this network"}, true
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

// DNSCheck compares what the network's resolvers say with a reference
// (resolved over the default route, ideally through a tunnel). The names
// are ones whose address never changes.
type DNSCheck struct {
	// Reference resolves name over a path the local network does not
	// control; nil disables the check.
	Reference func(ctx context.Context, name string) ([]netip.Addr, error)
	// Dial opens the UDP query socket (SO_MARK / interface set by the Linux
	// side); nil = net.Dialer.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// Names to ask; default pairs below.
	Names []string
	// Public is the resolver used for the "is port 53 diverted" question
	// (default 9.9.9.9:53).
	Public string
}

// Fixed names with stable addresses.
var defaultDNSNames = []string{"dns.google", "one.one.one.one"}

func (c *DNSCheck) ask(ctx context.Context, server, name string) ([]netip.Addr, error) {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), dns.TypeA)
	cl := &dns.Client{Net: "udp", Timeout: 3 * time.Second, Dialer: nil}
	var conn net.Conn
	var err error
	if c.Dial != nil {
		conn, err = c.Dial(ctx, "udp", server)
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
	if c.Reference == nil {
		return nil
	}
	names := c.Names
	if len(names) == 0 {
		names = defaultDNSNames
	}
	pub := c.Public
	if pub == "" {
		pub = "9.9.9.9:53"
	}
	var evs []Event
	var divertedAny, localDiff bool
	for _, name := range names {
		ref, err := c.Reference(ctx, name)
		if err != nil || len(ref) == 0 {
			continue
		}
		for _, s := range env.DNS {
			if _, _, err := net.SplitHostPort(s); err != nil {
				s = net.JoinHostPort(s, "53")
			}
			got, err := c.ask(ctx, s, name)
			if err == nil && len(got) > 0 && !overlap(got, ref) {
				localDiff = true
			}
		}
		got, err := c.ask(ctx, pub, name)
		if err == nil && len(got) > 0 && !overlap(got, ref) {
			divertedAny = true
		}
	}
	if localDiff {
		evs = append(evs, Event{Kind: KindDNSHijack, Severity: SevHigh, Proto: "udp", Port: 53,
			Detail: "the network's resolver answers differently from the reference for a fixed name"})
	}
	if divertedAny {
		evs = append(evs, Event{Kind: KindDNSHijack, Severity: SevHigh, Proto: "udp", Port: 53,
			Detail: "port 53 to a public resolver is answered with other data (diverted)"})
	}
	return evs
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
