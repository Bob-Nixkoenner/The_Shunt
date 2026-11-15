package daemon

import (
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/Bob-Nixkoenner/the_shunt/internal/engine"
	"github.com/Bob-Nixkoenner/the_shunt/internal/stats"
)

// WayCounter is optional for a Backend: it counts the traffic outside the
// tunnels, "direct" (internet) and "lan" (local network). On Linux an nft
// table of its own with counters only (nft.RenderWays). It never takes
// part in routing, marks or the kill switch: an error only means no
// numbers.
type WayCounter interface {
	// SetWays (re)loads the counting rules; the counters keep their values.
	SetWays(tunnelIfaces []string, endpoints []netip.Addr) error
	// ReadWays returns the byte counters (received, sent) since loading.
	ReadWays() (direct, lan stats.Bytes, err error)
	// WaysOff removes the counting rules.
	WaysOff() error
}

// waysIfaces returns the tunnel interfaces of a plan (sorted, unique):
// traffic through them is tunnel traffic. Tor routes have none.
func waysIfaces(p *engine.Plan) []string {
	if p == nil {
		return nil
	}
	var out []string
	for _, r := range p.Routes {
		if r.Kind == config.RouteTunnel && !r.Tor && r.Iface != "" {
			out = append(out, r.Iface)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// endpointAddrs turns the peers' endpoints ("ip:port", "[ip6]:port" or a
// bare address) into addresses; names and garbage are skipped.
func endpointAddrs(eps []string) []netip.Addr {
	var out []netip.Addr
	for _, e := range eps {
		if ap, err := netip.ParseAddrPort(e); err == nil {
			out = append(out, ap.Addr().Unmap())
		} else if a, err := netip.ParseAddr(e); err == nil {
			out = append(out, a.Unmap())
		}
	}
	slices.SortFunc(out, func(a, b netip.Addr) int { return a.Compare(b) })
	return slices.Compact(out)
}

func waysKey(ifaces []string, eps []netip.Addr) string {
	var b strings.Builder
	b.WriteString(strings.Join(ifaces, ","))
	b.WriteByte('|')
	for _, a := range eps {
		b.WriteString(a.String())
		b.WriteByte(',')
	}
	return b.String()
}

// countWays loads the counting rules when tunnels or endpoints changed and
// feeds the counters to the book (which takes the differences and treats a
// counter that went down as a restart). Called by checkHealth only (one at
// a time, healthBusy), outside d.mu.
func (d *Daemon) countWays(wc WayCounter, book *stats.Book, ifaces []string, eps []netip.Addr, now time.Time) {
	key := waysKey(ifaces, eps)
	if key != d.waysKey {
		if err := wc.SetWays(ifaces, eps); err != nil {
			if !d.waysWarned {
				d.Log.Warn("direct/local traffic not counted", "err", err)
				d.waysWarned = true
			}
			d.waysKey = ""
			return
		}
		d.waysKey, d.waysWarned = key, false
	}
	direct, lan, err := wc.ReadWays()
	if err != nil {
		d.waysKey = "" // gone (e.g. nft flush ruleset): load again next time
		return
	}
	book.Observe(stats.WayDirect, direct.RX, direct.TX, now)
	book.Observe(stats.WayLAN, lan.RX, lan.TX, now)
}
