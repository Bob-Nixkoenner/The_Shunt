// Package nft renders a plan into an nftables ruleset and applies it
// atomically via `nft -f`. Every Render* function returns a complete script
// that replaces its table in a single transaction: either the whole new
// ruleset is active or the old one stays.
package nft

import (
	"bytes"
	"fmt"
	"net/netip"
	"os/exec"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/Bob-Nixkoenner/the_shunt/internal/engine"
)

// Table names. Panic and lockdown live in their own tables so that a plan
// reload can never accidentally lift them.
const (
	Table         = "shunt"
	PanicTable    = "shunt_panic"
	LockdownTable = "shunt_lockdown"
	// EmergencyTable: tor-all, only the tor process reaches relays/bridges.
	EmergencyTable = "shunt_emerg"
	// ArpTable (family arp): see tunnelAddrGuard.
	ArpTable = "shunt_arp"
)

// Render produces the main ruleset for a plan.
func Render(p *engine.Plan) (string, error) {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }

	hasTor := false
	replaceHeader(&b, Table)
	w("table inet %s {", Table)
	// Domain rules: two sets per family ("a"/"b") so the DNS proxy can
	// extend an address's lifetime without a gap (see dnsproxy.pairSets).
	for _, r := range p.DomainRules() {
		for _, sfx := range []string{"a", "b"} {
			w("\tset %s {\n\t\ttype ipv4_addr; flags timeout;\n\t}", r.SetV4+sfx)
			w("\tset %s {\n\t\ttype ipv6_addr; flags timeout;\n\t}", r.SetV6+sfx)
		}
	}

	// --- classification: runs before the routing decision is final; a mark
	// change here makes the kernel re-route the packet.
	w("\tchain route_out {")
	w("\t\ttype route hook output priority mangle; policy accept;")
	w("\t\tmeta mark %#x return", engine.MarkBypass)
	// DHCP client traffic belongs to the local network: renewals go over
	// UDP (only the first DHCPv4 packets use raw sockets, which never get
	// here) and so does all of DHCPv6. Marked with a tunnel default route
	// it was dropped: leases ran out, DHCPv6 networks had no IPv6.
	// Unmarked it takes the main table; only root can bind these ports.
	w("\t\tudp sport 68 udp dport 67 return")
	w("\t\tudp sport 546 udp dport 547 return")
	// The same for IPv6 neighbour discovery (as the boot lockdown lets it
	// through): marked, router solicitations were dropped and direct apps
	// had no IPv6 on the local network.
	w("\t\ticmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } return")
	// Marked by shuntd itself (only CAP_NET_ADMIN can set a mark): a second
	// hop's encrypted packets entering the first tunnel, DNS upstream
	// queries. Remember it, so replies pass reverse path filtering.
	w("\t\tmeta mark and %#x == %#x ct mark set meta mark return", engine.MarkMask, engine.MarkBase)
	// A TCP connection keeps its route (sticky, also when a domain set
	// entry expires). Not UDP: there a "connection" is just a 5-tuple, and
	// a program reusing a port another program's flow just used would
	// inherit that flow's route – a way out of block or a tunnel. UDP is
	// classified by its socket, every packet.
	w("\t\tmeta l4proto tcp ct mark and %#x == %#x meta mark set ct mark return", engine.MarkMask, engine.MarkBase)
	// Answers to a connection that came in through a tunnel (UDP, ICMP
	// errors, echo replies) leave through it; mark_in marked the flow.
	// Unmarked they would take the main table: the tunnel address on the
	// local network.
	w("\t\tct direction reply oifname != \"lo\" ct mark and %#x == %#x meta mark set ct mark return", engine.MarkMask, engine.MarkBase)
	w("\t\tct direction reply return")
	if p.DNS {
		// DNS to a local stub (127.0.0.53) is classified too, so it can be
		// redirected to the right route's proxy below.
		w("\t\toifname \"lo\" meta l4proto != { tcp, udp } return")
		w("\t\toifname \"lo\" th dport != 53 return")
	} else {
		w("\t\toifname \"lo\" return")
	}
	dg, err := cgroupMatch(p.DaemonGroup)
	if err != nil {
		return "", err
	}
	w("\t\t%s return", dg)
	for _, r := range p.Rules {
		lines, err := ruleLines(r)
		if err != nil {
			return "", fmt.Errorf("rule %q: %w", r.Name, err)
		}
		for _, l := range lines {
			w("\t\t%s", l)
		}
	}
	if p.DefaultRoute.Kind != config.RouteDirect {
		w("\t\t%s", setMark(p.DefaultRoute.Mark))
	}
	w("\t}")

	// --- restore marks on incoming packets so rp_filter (src_valid_mark)
	// validates replies against the tunnel table, not the main table.
	w("\tchain mark_in {")
	w("\t\ttype filter hook prerouting priority mangle; policy accept;")
	// not on loopback: a query redirected to a DNS proxy keeps the mark of
	// its own route there (the proxy reads it, SO_RCVMARK); the conntrack
	// entry it joined may belong to another route's query
	w("\t\tiifname \"lo\" return")
	// A connection started from the far side of a tunnel belongs to that
	// tunnel: its answers (SYN-ACK, RST, ICMP) go back through it.
	for _, r := range p.Routes {
		if r.Kind == config.RouteTunnel && !r.Forward && r.Iface != "" {
			if err := checkIdent(r.Iface); err != nil {
				return "", err
			}
			w("\t\tiifname %q ct state new ct mark set %#x", r.Iface, r.Mark)
		}
	}
	// Forwarded traffic (containers, VMs and other devices behind this
	// machine) is not seen by route_out, which only classifies local
	// sockets: it took the main table, past the tunnel and its kill switch.
	// A new forwarded connection gets the default route's mark (the same
	// way, via the tunnel's table or into its kill switch). Not what comes
	// in from a tunnel, from loopback, or for this machine itself.
	if p.DefaultRoute.Kind != config.RouteDirect {
		skip := []string{`"lo"`}
		for _, r := range p.Routes {
			if r.Kind == config.RouteTunnel && r.Iface != "" && checkIdent(r.Iface) == nil {
				skip = append(skip, fmt.Sprintf("%q", r.Iface))
			}
		}
		w("\t\tiifname != { %s } fib daddr type != local ct state new ct mark and %#x != %#x meta mark set %#x ct mark set meta mark",
			strings.Join(skip, ", "), engine.MarkMask, engine.MarkBase, p.DefaultRoute.Mark)
	}
	w("\t\tct mark and %#x == %#x meta mark set ct mark", engine.MarkMask, engine.MarkBase)
	// Tailscale tunnels: what tailscaled (in its own namespace) sends
	// arrives on the veth. It leaves like Shunt's own encrypted packets:
	// bypass, or through the tunnel it is routed via.
	for _, r := range p.Routes {
		if r.Kind == config.RouteTunnel && r.Forward {
			if err := checkIdent(r.Iface); err != nil {
				return "", err
			}
			w("\t\tiifname %q meta mark set %#x", r.Iface, r.FwdMark)
		}
	}
	w("\t}")

	tunnelAddrGuard(w, p)

	// Tailscale tunnels need forwarding on the uplinks (the replies of
	// their encrypted packets arrive there). The machine is no router:
	// nothing may start a new connection through it from those
	// interfaces, except what was set up on purpose (DNAT, port forwards).
	if ups := p.Uplinks(); len(ups) > 0 {
		for _, u := range ups {
			if err := checkIdent(u); err != nil {
				return "", err
			}
		}
		w("\tchain fwd_guard {")
		w("\t\ttype filter hook forward priority filter; policy accept;")
		w("\t\tct status dnat return")
		w("\t\tiifname { %s } ct state new counter drop", quoteList(ups))
		w("\t}")
	}

	// Old ICMP requests that nothing needs any more but whose answers tell a
	// neighbour the system's clock (timestamp, down to milliseconds: uptime
	// and clock fingerprint), netmask or existence: not answered.
	w("\tchain icmp_quiet {")
	w("\t\ttype filter hook input priority raw; policy accept;")
	w("\t\ticmp type { timestamp-request, address-mask-request, info-request } counter drop")
	w("\t}")

	if p.Inbound != nil {
		lines, err := inboundLines(p.Inbound)
		if err != nil {
			return "", err
		}
		w("\tchain inbound {")
		w("\t\ttype filter hook input priority filter; policy accept;")
		for _, l := range lines {
			w("\t\t%s", l)
		}
		w("\t}")
	}

	// --- enforcement: the block route.
	// ask_out holds the app firewall's waiting programs (filled at run time
	// by the daemon, see AskRules); loopback stays open (DNS to the proxy).
	w("\tchain ask_out {")
	w("\t}")
	w("\tchain filter_out {")
	w("\t\ttype filter hook output priority filter; policy accept;")
	w("\t\tmeta mark %#x counter reject with icmpx admin-prohibited", engine.MarkBlock)
	// Tor carries TCP only (and DNS, answered by the proxy on loopback):
	// UDP and the rest are rejected at once, so QUIC falls back to TCP.
	// "fib daddr type != local", not "oifname != lo": a DNS query redirected
	// to the proxy on loopback still reports the interface from before the
	// redirect (eth0) here, and a resolver on the LAN would be rejected.
	for _, r := range p.Routes {
		if r.Tor {
			w("\t\tmeta mark %#x fib daddr type != local meta l4proto != tcp counter reject with icmpx admin-prohibited", r.Mark)
		}
	}
	w("\t\toifname != \"lo\" jump ask_out")
	if p.BlockDoT {
		w("\t\t%s accept", dg)
		w("\t\tmeta l4proto { tcp, udp } th dport 853 counter reject with icmpx admin-prohibited")
	}
	w("\t}")

	if p.DNS {
		// --- every DNS query goes to the proxy listener of its route; the
		// proxy decides the upstream. Nothing on port 53 leaves directly.
		w("\tchain dns_redirect {")
		w("\t\ttype nat hook output priority dstnat; policy accept;")
		lines, err := dnsRedirectLines(p, true)
		if err != nil {
			return "", err
		}
		for _, l := range lines {
			w("\t\t%s", l)
		}
		w("\t}")
	}

	// --- Tor routes: TCP goes to shuntd's transparent proxy, which hands it
	// to tor. After the DNS redirect (a priority later), which owns port 53.
	for _, r := range p.Routes {
		if !r.Tor {
			continue
		}
		if !hasTor {
			w("\tchain tor_redirect {")
			w("\t\ttype nat hook output priority dstnat + 1; policy accept;")
			hasTor = true
		}
		// a rule's own port first (its apps keep their own circuits)
		for _, ru := range p.Rules {
			if ru.ProxyPort == 0 || ru.Route != r {
				continue
			}
			for _, g := range ru.Groups {
				m, err := cgroupMatch(g)
				if err != nil {
					return "", err
				}
				w("\t\t%s meta mark %#x meta l4proto tcp th dport != 53 redirect to :%d", m, r.Mark, ru.ProxyPort)
			}
		}
		w("\t\tmeta mark %#x meta l4proto tcp th dport != 53 redirect to :%d", r.Mark, r.ProxyPort)
	}
	if hasTor {
		w("\t}")
	}

	// --- belt and braces: tunnel traffic must really leave through its
	// tunnel interface. This has to be postrouting: in the output hook the
	// kernel still reports the interface from *before* the re-route.
	w("\tchain leak_guard {")
	w("\t\ttype filter hook postrouting priority filter; policy accept;")
	for _, r := range p.Routes {
		if r.Kind == config.RouteLink {
			// a link route leaves through its interface or not at all
			if r.Iface == "" {
				w("\t\tmeta mark %#x oifname != \"lo\" counter drop", r.Mark)
				continue
			}
			if err := checkIdent(r.Iface); err != nil {
				return "", err
			}
			w("\t\tmeta mark %#x oifname != { %q, \"lo\" } counter drop", r.Mark, r.Iface)
			continue
		}
		if r.Kind != config.RouteTunnel {
			continue
		}
		if r.Tor {
			// only the redirect to shuntd (loopback) may leave
			w("\t\tmeta mark %#x oifname != \"lo\" counter drop", r.Mark)
			continue
		}
		if err := checkIdent(r.Iface); err != nil {
			return "", err
		}
		if r.AllowLAN {
			// allow_lan: private destinations may leave elsewhere (the
			// routing table only sends directly attached networks there)
			w("\t\tmeta mark %#x oifname != { %q, \"lo\" } meta nfproto ipv4 ip daddr != { %s } counter drop", r.Mark, r.Iface, strings.Join(engine.LANv4, ", "))
			w("\t\tmeta mark %#x oifname != { %q, \"lo\" } meta nfproto ipv6 ip6 daddr != { %s } counter drop", r.Mark, r.Iface, strings.Join(engine.LANv6, ", "))
			continue
		}
		w("\t\tmeta mark %#x oifname != { %q, \"lo\" } counter drop", r.Mark, r.Iface)
	}
	w("\t}")

	// --- MSS clamping: a classified socket wrote its MSS into the SYN for
	// the physical route (e.g. 1460 for MTU 1500) before it was re-routed
	// into a tunnel with a smaller MTU. The far end then sends segments
	// that don't fit the tunnel: stalls on TLS handshakes and downloads
	// where the path drops the ICMP "fragmentation needed". Set the MSS to
	// what the tunnel route carries (rt mtu = the MTU after re-routing).
	w("\tchain mss_clamp {")
	w("\t\ttype filter hook postrouting priority mangle; policy accept;")
	for _, r := range p.Routes {
		if r.Kind == config.RouteTunnel && !r.Tor {
			w("\t\toifname %q tcp flags syn / syn,rst tcp option maxseg size set rt mtu", r.Iface)
		}
	}
	w("\t}")

	// --- source NAT: classified sockets already picked the physical source
	// address before being re-routed into the tunnel.
	w("\tchain nat_post {")
	w("\t\ttype nat hook postrouting priority srcnat; policy accept;")
	for _, r := range p.Routes {
		if (r.Kind == config.RouteTunnel || r.Kind == config.RouteLink) && r.Iface != "" {
			w("\t\tmeta mark %#x oifname %q masquerade", r.Mark, r.Iface)
		}
		if r.Kind == config.RouteTunnel && r.Forward && r.Iface != "" {
			w("\t\tiifname %q oifname != %q masquerade", r.Iface, r.Iface)
		}
	}
	w("\t}")
	w("}")
	arpGuard(&b, p)
	return b.String(), nil
}

func setMark(m uint32) string {
	return fmt.Sprintf("meta mark set %#x ct mark set meta mark accept", m)
}

func ruleLines(r engine.Rule) ([]string, error) {
	if r.Route == nil {
		return nil, nil // only sets a DNS filter level (see dns_redirect)
	}
	groups := []string{""}
	if len(r.Groups) > 0 {
		groups = groups[:0]
		for _, g := range r.Groups {
			m, err := cgroupMatch(g)
			if err != nil {
				return nil, err
			}
			groups = append(groups, m)
		}
	}
	dsts := []string{""}
	if len(r.Domains) > 0 {
		dsts = []string{"ip daddr @" + r.SetV4 + "a", "ip daddr @" + r.SetV4 + "b", "ip6 daddr @" + r.SetV6 + "a", "ip6 daddr @" + r.SetV6 + "b"}
	} else if !r.AnyFamily {
		dsts = dsts[:0]
		if len(r.V4) > 0 {
			dsts = append(dsts, "ip daddr "+prefixSet(r.V4))
		}
		if len(r.V6) > 0 {
			dsts = append(dsts, "ip6 daddr "+prefixSet(r.V6))
		}
	}
	ports := []string{""}
	if len(r.Ports) > 0 {
		ports = ports[:0]
		byProto := map[string][]string{}
		for _, p := range r.Ports {
			s := fmt.Sprint(p.From)
			if p.To != p.From {
				s = fmt.Sprintf("%d-%d", p.From, p.To)
			}
			byProto[p.Proto] = append(byProto[p.Proto], s)
		}
		for _, proto := range []string{"tcp", "udp"} {
			if ps := byProto[proto]; len(ps) > 0 {
				ports = append(ports, fmt.Sprintf("meta l4proto %s th dport { %s }", proto, strings.Join(ps, ", ")))
			}
		}
	}
	var out []string
	for _, g := range groups {
		for _, d := range dsts {
			for _, p := range ports {
				parts := []string{}
				for _, s := range []string{g, d, p} {
					if s != "" {
						parts = append(parts, s)
					}
				}
				parts = append(parts, setMark(r.Route.Mark))
				out = append(out, strings.Join(parts, " "))
			}
		}
	}
	return out, nil
}

func prefixSet(ps []netip.Prefix) string {
	s := make([]string, len(ps))
	for i, p := range ps {
		s[i] = p.String()
	}
	sort.Strings(s)
	return "{ " + strings.Join(s, ", ") + " }"
}

func cgroupMatch(g engine.Group) (string, error) {
	if err := checkIdent(g.Path); err != nil {
		return "", err
	}
	return fmt.Sprintf("socket cgroupv2 level %d %q", g.Level(), g.Path), nil
}

// checkIdent rejects strings that could break out of an nft quoted string.
func checkIdent(s string) error {
	if s == "" || strings.ContainsAny(s, "\"\\\n\r;{}") {
		return fmt.Errorf("unsafe identifier %q", s)
	}
	return nil
}

func replaceHeader(b *strings.Builder, table string) { replaceHeaderIn(b, "inet", table) }

func replaceHeaderIn(b *strings.Builder, family, table string) {
	// "add" creates the table if missing so "delete" never fails; both run in
	// the same transaction as the new definition.
	fmt.Fprintf(b, "table %s %s\ndelete table %s %s\n", family, table, family, table)
}

// Strict describes a "nothing gets out except ..." ruleset. Panic, boot
// lockdown and the emergency mode (only the tor process, only to its
// relays) are the same thing with different exceptions.
type Strict struct {
	Table    string
	Priority int  // output hook priority (before the main ruleset)
	Inbound  bool // also drop input (except lo) and forwarding
	DHCP     bool // DHCPv4/v6 client traffic
	ND       bool // IPv6 neighbour discovery
	// LocalDst: packets to 127/8 and ::1 pass whatever the interface. After
	// the main table's redirect to a local proxy the route (and so the
	// interface) was chosen for the original destination, not lo.
	LocalDst bool
	// Only the processes in AllowCgroup may reach AllowDst, and only they
	// (emergency mode: the tor process and its guards/bridges). Both must be
	// set; an empty AllowDst with a cgroup lets nothing through.
	AllowCgroup engine.Group
	AllowDst    []netip.Prefix
}

// RenderStrict renders s: policy drop on output (and input/forward if
// Inbound) with only loopback and the listed exceptions.
func RenderStrict(s Strict) (string, error) {
	var b strings.Builder
	replaceHeader(&b, s.Table)
	fmt.Fprintf(&b, "table inet %s {\n\tchain out {\n\t\ttype filter hook output priority %d; policy drop;\n\t\toifname \"lo\" accept\n", s.Table, s.Priority)
	if s.DHCP {
		b.WriteString("\t\tudp sport 68 udp dport 67 accept\n\t\tudp sport 546 udp dport 547 accept\n")
	}
	if s.ND {
		b.WriteString("\t\ticmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } accept\n")
	}
	if s.LocalDst {
		b.WriteString("\t\tip daddr 127.0.0.0/8 accept\n\t\tip6 daddr ::1 accept\n")
	}
	if s.AllowCgroup.Path != "" && len(s.AllowDst) > 0 {
		m, err := cgroupMatch(s.AllowCgroup)
		if err != nil {
			return "", err
		}
		var v4, v6 []netip.Prefix
		for _, p := range s.AllowDst {
			if p.Addr().Is4() {
				v4 = append(v4, p)
			} else {
				v6 = append(v6, p)
			}
		}
		if len(v4) > 0 {
			fmt.Fprintf(&b, "\t\t%s ip daddr %s accept\n", m, prefixSet(v4))
		}
		if len(v6) > 0 {
			fmt.Fprintf(&b, "\t\t%s ip6 daddr %s accept\n", m, prefixSet(v6))
		}
	}
	b.WriteString("\t}\n")
	if s.Inbound {
		fmt.Fprintf(&b, "\tchain in {\n\t\ttype filter hook input priority %d; policy drop;\n\t\tiifname \"lo\" accept\n\t}\n", s.Priority)
		fmt.Fprintf(&b, "\tchain fwd_drop {\n\t\ttype filter hook forward priority %d; policy drop;\n\t}\n", s.Priority)
	}
	b.WriteString("}\n")
	return b.String(), nil
}

// RenderPanic drops everything except loopback, in and out.
func RenderPanic() string {
	out, _ := RenderStrict(Strict{Table: PanicTable, Priority: -300, Inbound: true})
	return out
}

// RenderEmergency is the tor-all ruleset: after the main ruleset's redirect
// to the Tor proxy (the redirected packets still leave via the original route; LocalDst lets them through; the packets of the apps already on
// loopback), everything that leaves the machine is dropped except DHCP, IPv6
// neighbour discovery and the processes in torGroup talking to dst (relays
// or bridges). Nothing falls back to direct, whatever happens to tor,
// the tunnels or the main table; the table stays when shuntd stops.
func RenderEmergency(torGroup engine.Group, dst []netip.Prefix) (string, error) {
	return RenderStrict(Strict{Table: EmergencyTable, Priority: 10, DHCP: true, ND: true, LocalDst: true, AllowCgroup: torGroup, AllowDst: dst})
}

// RenderLockdown is the boot-time ruleset: nothing but loopback, DHCP and
// IPv6 neighbour discovery until shuntd has applied its plan.
func RenderLockdown() string {
	out, _ := RenderStrict(Strict{Table: LockdownTable, Priority: -290, DHCP: true, ND: true})
	return out
}

// dnsRedirectLines are the rules of the dns_redirect chain. Without direct
// (shuntd stopped) the queries of direct traffic are left alone and reach
// the system resolver, while those of tunnels, links and the login browser
// still go to their (now closed) proxy port: DNS fails closed only there.
func dnsRedirectLines(p *engine.Plan, direct bool) ([]string, error) {
	dg, err := cgroupMatch(p.DaemonGroup)
	if err != nil {
		return nil, err
	}
	out := []string{dg + " return"}
	add := func(format string, a ...any) { out = append(out, fmt.Sprintf(format, a...)) }
	// Rules with their own DNS filter level: their programs' queries go
	// to a copy of the route's listener that filters at that level.
	for _, r := range p.Rules {
		for _, g := range r.Groups {
			cg, err := cgroupMatch(g)
			if err != nil {
				return nil, fmt.Errorf("rule %q: %w", r.Name, err)
			}
			for _, fr := range r.FilterRoutes {
				if fr.Kind == config.RouteDirect && !direct {
					continue
				}
				add("%s meta mark %#x meta l4proto { tcp, udp } th dport 53 redirect to :%d", cg, fr.Mark, fr.DNSPort)
				if fr.Kind == config.RouteDirect {
					add("%s meta mark and %#x != %#x meta l4proto { tcp, udp } th dport 53 redirect to :%d", cg, engine.MarkMask, engine.MarkBase, fr.DNSPort)
				}
			}
		}
	}
	var dr *engine.Route
	for _, r := range p.Routes {
		if r.Kind == config.RouteDirect {
			dr = r
			if !direct {
				continue
			}
		}
		if r.Kind == config.RouteBlock {
			continue // rejected in filter_out anyway
		}
		add("meta mark %#x meta l4proto { tcp, udp } th dport 53 redirect to :%d", r.Mark, r.DNSPort)
	}
	if p.Captive != nil {
		add("meta mark %#x meta l4proto { tcp, udp } th dport 53 redirect to :%d", p.Captive.Mark, p.Captive.DNSPort)
	}
	if direct && dr != nil {
		add("meta mark and %#x != %#x meta l4proto { tcp, udp } th dport 53 redirect to :%d", engine.MarkMask, engine.MarkBase, dr.DNSPort)
	}
	return out, nil
}

// StoppedDNS replaces the dns_redirect chain for the time shuntd is down:
// the kill switch stays for tunnels, but direct traffic keeps working
// including name resolution (see dnsRedirectLines). Empty if the plan
// has no DNS proxy.
func StoppedDNS(p *engine.Plan) (string, error) {
	if !p.DNS {
		return "", nil
	}
	lines, err := dnsRedirectLines(p, false)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "flush chain inet %s dns_redirect\n", Table)
	for _, l := range lines {
		fmt.Fprintf(&b, "add rule inet %s dns_redirect %s\n", Table, l)
	}
	return b.String(), nil
}

// DeleteScript removes a table if it exists.
func DeleteScript(table string) string {
	var b strings.Builder
	replaceHeader(&b, table)
	return b.String()
}

// DeleteArpScript removes ArpTable.
func DeleteArpScript() string {
	var b strings.Builder
	replaceHeaderIn(&b, "arp", ArpTable)
	return b.String()
}

// Apply runs a script through `nft -f -` as one transaction.
func Apply(script string) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// AskLogGroup is the NFLOG group of the app firewall's waiting programs.
const AskLogGroup = 5301

// AskRules replaces the rules of the ask_out chain: every waiting group
// (cgroup path → id) logs its first packets to AskLogGroup with prefix
// "ask:<id> " and is rejected.
func AskRules(groups map[string]engine.Group) (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "flush chain inet %s ask_out\n", Table)
	ids := make([]string, 0, len(groups))
	for id := range groups {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		m, err := cgroupMatch(groups[id])
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "add rule inet %s ask_out %s limit rate 5/second burst 10 packets log prefix \"ask:%s \" group %d\n", Table, m, id, AskLogGroup)
		fmt.Fprintf(&b, "add rule inet %s ask_out %s counter reject with icmpx port-unreachable\n", Table, m)
	}
	return b.String(), nil
}

func quoteList(l []string) string {
	q := make([]string, len(l))
	for i, s := range l {
		q[i] = fmt.Sprintf("%q", s)
	}
	return strings.Join(q, ", ")
}

// inboundLines filters what arrives on the uplinks and tunnels: answers to
// your own connections and what the network needs to keep you connected
// (DHCP, IPv6 neighbour discovery, ICMP errors) pass, the rest per mode.
// Dropped, not rejected: a closed machine does not answer scans.
func inboundLines(in *engine.Inbound) ([]string, error) {
	ifs := slices.Clone(in.Uplinks)
	for _, t := range in.Tunnels {
		ifs = append(ifs, t.Iface)
	}
	if len(ifs) == 0 {
		return nil, nil
	}
	for _, i := range ifs {
		if err := checkIdent(i); err != nil {
			return nil, err
		}
	}
	out := []string{
		fmt.Sprintf("iifname != { %s } return", quoteList(ifs)),
		"ct state established,related accept",
		"meta l4proto ipv6-icmp icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept",
		"meta l4proto icmp icmp type { destination-unreachable, time-exceeded, parameter-problem } accept",
		"meta nfproto ipv4 udp sport 67 udp dport 68 accept",
		"meta nfproto ipv6 udp sport 547 udp dport 546 accept",
	}
	// every tunnel ends here (accept or drop): what follows is the uplinks
	for _, t := range in.Tunnels {
		m := fmt.Sprintf("iifname %q ", t.Iface)
		out = append(out, modeLines(m, t.Mode, t.Allow)...)
	}
	return append(out, modeLines("", in.Mode, in.Allow)...), nil
}

// modeLines lets in what mode allows (lan: ping and the ports in allow
// from private addresses), the rest is dropped; prefix narrows them to
// one interface.
func modeLines(prefix, mode string, allow []config.PortSel) []string {
	if mode == config.InboundOpen {
		return []string{prefix + "accept"}
	}
	var out []string
	if mode == config.InboundLAN {
		v4, v6 := strings.Join(engine.LANv4, ", "), strings.Join(engine.LANv6, ", ")
		out = append(out,
			fmt.Sprintf("%sip saddr { %s } icmp type echo-request accept", prefix, v4),
			fmt.Sprintf("%sip6 saddr { %s } icmpv6 type echo-request accept", prefix, v6))
		for _, a := range allow {
			port := strconv.Itoa(int(a.From))
			if a.To != a.From {
				port += "-" + strconv.Itoa(int(a.To))
			}
			out = append(out,
				fmt.Sprintf("%sip saddr { %s } %s dport %s accept", prefix, v4, a.Proto, port),
				fmt.Sprintf("%sip6 saddr { %s } %s dport %s accept", prefix, v6, a.Proto, port))
		}
	}
	return append(out, prefix+"counter drop")
}

// tunnelAddrs: the interfaces of the tunnels and their own addresses.
func tunnelAddrs(p *engine.Plan) (ifs, v4, v6 []string) {
	seen := map[string]bool{}
	for _, r := range p.Routes {
		if r.Kind != config.RouteTunnel || r.Iface == "" || checkIdent(r.Iface) != nil {
			continue
		}
		ifs = append(ifs, fmt.Sprintf("%q", r.Iface))
		for _, a := range r.Addrs {
			a = a.Unmap()
			if seen[a.String()] {
				continue
			}
			seen[a.String()] = true
			if a.Is4() {
				v4 = append(v4, a.String())
			} else {
				v6 = append(v6, a.String())
			}
		}
	}
	return
}

// tunnelAddrGuard keeps the tunnels' own addresses off the local network.
// Linux answers for any local address on any interface (weak host model): a
// neighbour on the cafe Wi-Fi could ask "who has 10.66.0.12?" (ARP) and learn
// that this machine uses a VPN and which address, or send packets to it
// (CVE-2019-14899: inferring TCP connections inside the tunnel). Only the
// tunnel interfaces themselves may reach those addresses. This is the IP
// part, a chain of the main table.
func tunnelAddrGuard(w func(string, ...any), p *engine.Plan) {
	ifs, v4, v6 := tunnelAddrs(p)
	if len(v4)+len(v6) == 0 {
		return
	}
	pass := strings.Join(append([]string{`"lo"`}, ifs...), ", ")
	w("\tchain tunnel_addr_guard {")
	w("\t\ttype filter hook prerouting priority raw; policy accept;")
	if len(v4) > 0 {
		w("\t\tiifname != { %s } ip daddr { %s } counter drop", pass, strings.Join(v4, ", "))
	}
	if len(v6) > 0 {
		w("\t\tiifname != { %s } ip6 daddr { %s } counter drop", pass, strings.Join(v6, ", "))
	}
	w("\t}")
}

// arpGuard is the ARP part, a table of the arp family (loaded in the same
// transaction; replaced on every plan, so a removed tunnel's address is free
// again): ARP requests for a tunnel address are not answered.
func arpGuard(b *strings.Builder, p *engine.Plan) {
	replaceHeaderIn(b, "arp", ArpTable)
	ifs, v4, _ := tunnelAddrs(p)
	if len(v4) == 0 {
		return
	}
	pass := strings.Join(append([]string{`"lo"`}, ifs...), ", ")
	fmt.Fprintf(b, "table arp %s {\n\tchain in {\n\t\ttype filter hook input priority filter; policy accept;\n", ArpTable)
	fmt.Fprintf(b, "\t\tiifname != { %s } arp operation request arp daddr ip { %s } counter drop\n\t}\n}\n", pass, strings.Join(v4, ", "))
}
