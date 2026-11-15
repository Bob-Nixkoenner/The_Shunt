package nft

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os/exec"
	"slices"
	"strings"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/Bob-Nixkoenner/the_shunt/internal/engine"
)

// WaysTable counts traffic outside the tunnels: "direct" (internet) and
// "lan" (local network). It is a table of its own with nothing but
// counters: no verdict, no mark, no NAT. It can neither let a packet out
// nor stop one, and the main table never depends on it.
const WaysTable = "shunt_ways"

// Counter names in WaysTable.
const (
	WayDirectRX = "direct_rx"
	WayDirectTX = "direct_tx"
	WayLANRX    = "lan_rx"
	WayLANTX    = "lan_tx"
)

// Destinations (and sources) that count as local network: private,
// loopback, link-local, multicast, broadcast, unspecified (as
// splitstack.isLocalAddr on Windows/Android).
var (
	waysLANv4 = []string{"0.0.0.0/32", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "255.255.255.255/32"}
	waysLANv6 = []string{"::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8"}
)

// Ways is what the counting table needs to know.
type Ways struct {
	// TunnelIfaces: traffic through these interfaces is tunnel traffic.
	TunnelIfaces []string
	// Endpoints: the tunnels' outer packets (to and from their servers)
	// are tunnel traffic too, not direct.
	Endpoints []netip.Addr
}

// WaysFromPlan returns the tunnel interfaces of a plan (sorted, unique).
func WaysFromPlan(p *engine.Plan) []string {
	var out []string
	for _, r := range p.Routes {
		if r.Iface != "" && !r.Tor && r.Kind == config.RouteTunnel {
			out = append(out, r.Iface)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// RenderWays builds the script for WaysTable. Running it again keeps the
// counters (an existing named counter is not reset by "add") and replaces
// the rules, so a new tunnel or endpoint does not lose the totals.
//
// Only local traffic counts: sent (postrouting, source address is this
// machine, before source NAT) and received (input, after the filters that
// may drop it). Loopback, tunnel interfaces, packets with the bypass mark
// (a tunnel's own encrypted packets) and packets to/from tunnel endpoints
// are left out.
func RenderWays(w Ways) (string, error) {
	ifs := []string{`"lo"`}
	for _, i := range w.TunnelIfaces {
		if err := checkIdent(i); err != nil {
			return "", err
		}
		ifs = append(ifs, fmt.Sprintf("%q", i))
	}
	var ep4, ep6 []string
	for _, a := range w.Endpoints {
		a = a.Unmap()
		switch {
		case !a.IsValid():
		case a.Is4():
			ep4 = append(ep4, a.String())
		default:
			ep6 = append(ep6, a.WithZone("").String())
		}
	}
	slices.Sort(ep4)
	ep4 = slices.Compact(ep4)
	slices.Sort(ep6)
	ep6 = slices.Compact(ep6)

	var b strings.Builder
	w2 := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	t := "inet " + WaysTable
	w2("add table %s", t)
	for _, c := range []string{WayDirectRX, WayDirectTX, WayLANRX, WayLANTX} {
		w2("add counter %s %s", t, c)
	}
	w2("add chain %s out { type filter hook postrouting priority filter + 10; policy accept; }", t)
	w2("flush chain %s out", t)
	w2("add chain %s in { type filter hook input priority filter + 10; policy accept; }", t)
	w2("flush chain %s in", t)

	type fam struct {
		proto, ip string
		lan, eps  []string
	}
	for _, f := range []fam{{"ipv4", "ip", waysLANv4, ep4}, {"ipv6", "ip6", waysLANv6, ep6}} {
		lan := strings.Join(f.lan, ", ")
		out := fmt.Sprintf("meta nfproto %s oifname != { %s } meta mark != %#x fib saddr type local", f.proto, strings.Join(ifs, ", "), engine.MarkBypass)
		in := fmt.Sprintf("meta nfproto %s iifname != { %s }", f.proto, strings.Join(ifs, ", "))
		if len(f.eps) > 0 {
			e := strings.Join(f.eps, ", ")
			out += fmt.Sprintf(" %s daddr != { %s }", f.ip, e)
			in += fmt.Sprintf(" %s saddr != { %s }", f.ip, e)
		}
		w2("add rule %s out %s %s daddr { %s } counter name %s", t, out, f.ip, lan, WayLANTX)
		w2("add rule %s out %s %s daddr != { %s } counter name %s", t, out, f.ip, lan, WayDirectTX)
		w2("add rule %s in %s %s saddr { %s } counter name %s", t, in, f.ip, lan, WayLANRX)
		w2("add rule %s in %s %s saddr != { %s } counter name %s", t, in, f.ip, lan, WayDirectRX)
	}
	return b.String(), nil
}

// WaysOffScript removes WaysTable.
func WaysOffScript() string { return DeleteScript(WaysTable) }

// WayBytes are the byte counts of WaysTable.
type WayBytes struct {
	DirectRX, DirectTX, LANRX, LANTX int64
}

// ParseWays reads the counters from `nft -j list table inet shunt_ways`.
// All four must be there, or the table is not (fully) loaded.
func ParseWays(js []byte) (WayBytes, error) {
	var doc struct {
		Nftables []struct {
			Counter *struct {
				Family string `json:"family"`
				Table  string `json:"table"`
				Name   string `json:"name"`
				Bytes  uint64 `json:"bytes"`
			} `json:"counter"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(js, &doc); err != nil {
		return WayBytes{}, err
	}
	var w WayBytes
	found := 0
	for _, o := range doc.Nftables {
		c := o.Counter
		if c == nil || c.Table != WaysTable || c.Family != "inet" {
			continue
		}
		v := int64(c.Bytes & (1<<63 - 1)) // stays positive; a wrap counts as a reset
		switch c.Name {
		case WayDirectRX:
			w.DirectRX = v
		case WayDirectTX:
			w.DirectTX = v
		case WayLANRX:
			w.LANRX = v
		case WayLANTX:
			w.LANTX = v
		default:
			continue
		}
		found++
	}
	if found != 4 {
		return WayBytes{}, fmt.Errorf("nft: %s: %d of 4 counters", WaysTable, found)
	}
	return w, nil
}

// ReadWays lists WaysTable and parses its counters.
func ReadWays() (WayBytes, error) {
	out, err := exec.Command("nft", "-j", "list", "table", "inet", WaysTable).Output()
	if err != nil {
		return WayBytes{}, fmt.Errorf("nft list %s: %w", WaysTable, err)
	}
	return ParseWays(out)
}
