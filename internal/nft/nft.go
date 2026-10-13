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
	"sort"
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
)

// Render produces the main ruleset for a plan.
func Render(p *engine.Plan) (string, error) {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }

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
	// Marked by shuntd itself (only CAP_NET_ADMIN can set a mark): a second
	// hop's encrypted packets entering the first tunnel, DNS upstream
	// queries. Remember it, so replies pass reverse path filtering.
	w("\t\tmeta mark and %#x == %#x ct mark set meta mark return", engine.MarkMask, engine.MarkBase)
	w("\t\tct mark and %#x == %#x meta mark set ct mark return", engine.MarkMask, engine.MarkBase)
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
	w("\t\tct mark and %#x == %#x meta mark set ct mark", engine.MarkMask, engine.MarkBase)
	w("\t}")

	// --- enforcement: the block route.
	// ask_out holds the app firewall's waiting programs (filled at run time
	// by the daemon, see AskRules); loopback stays open (DNS to the proxy).
	w("\tchain ask_out {")
	w("\t}")
	w("\tchain filter_out {")
	w("\t\ttype filter hook output priority filter; policy accept;")
	w("\t\tmeta mark %#x counter reject with icmpx admin-prohibited", engine.MarkBlock)
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
		w("\t\t%s return", dg)
		var direct *engine.Route
		for _, r := range p.Routes {
			if r.Kind == config.RouteDirect {
				direct = r
			}
			if r.Kind == config.RouteBlock {
				continue // rejected in filter_out anyway
			}
			w("\t\tmeta mark %#x meta l4proto { tcp, udp } th dport 53 redirect to :%d", r.Mark, r.DNSPort)
		}
		if p.Captive != nil {
			w("\t\tmeta mark %#x meta l4proto { tcp, udp } th dport 53 redirect to :%d", p.Captive.Mark, p.Captive.DNSPort)
		}
		w("\t\tmeta mark and %#x != %#x meta l4proto { tcp, udp } th dport 53 redirect to :%d", engine.MarkMask, engine.MarkBase, direct.DNSPort)
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

	// --- source NAT: classified sockets already picked the physical source
	// address before being re-routed into the tunnel.
	w("\tchain nat_post {")
	w("\t\ttype nat hook postrouting priority srcnat; policy accept;")
	for _, r := range p.Routes {
		if (r.Kind == config.RouteTunnel || r.Kind == config.RouteLink) && r.Iface != "" {
			w("\t\tmeta mark %#x oifname %q masquerade", r.Mark, r.Iface)
		}
	}
	w("\t}")
	w("}")
	return b.String(), nil
}

func setMark(m uint32) string {
	return fmt.Sprintf("meta mark set %#x ct mark set meta mark accept", m)
}

func ruleLines(r engine.Rule) ([]string, error) {
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

func replaceHeader(b *strings.Builder, table string) {
	// "add" creates the table if missing so "delete" never fails; both run in
	// the same transaction as the new definition.
	fmt.Fprintf(b, "table inet %s\ndelete table inet %s\n", table, table)
}

// RenderPanic drops everything except loopback, in and out.
func RenderPanic() string {
	var b strings.Builder
	replaceHeader(&b, PanicTable)
	fmt.Fprintf(&b, `table inet %s {
	chain out {
		type filter hook output priority -300; policy drop;
		oifname "lo" accept
	}
	chain in {
		type filter hook input priority -300; policy drop;
		iifname "lo" accept
	}
}
`, PanicTable)
	return b.String()
}

// RenderLockdown is the boot-time ruleset: nothing but loopback, DHCP and
// IPv6 neighbour discovery until shuntd has applied its plan.
func RenderLockdown() string {
	var b strings.Builder
	replaceHeader(&b, LockdownTable)
	fmt.Fprintf(&b, `table inet %s {
	chain out {
		type filter hook output priority -290; policy drop;
		oifname "lo" accept
		udp sport 68 udp dport 67 accept
		udp sport 546 udp dport 547 accept
		icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } accept
	}
}
`, LockdownTable)
	return b.String()
}

// DeleteScript removes a table if it exists.
func DeleteScript(table string) string {
	var b strings.Builder
	replaceHeader(&b, table)
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
