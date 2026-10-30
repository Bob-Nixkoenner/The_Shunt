package daemon

import (
	"errors"
	"net/netip"
	"path/filepath"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/check"
	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/Bob-Nixkoenner/the_shunt/internal/engine"
	"github.com/Bob-Nixkoenner/the_shunt/internal/tunnel"
)

// Emergencer is implemented by backends that can run tor-all as a strict
// emergency mode: besides the redirect of every app into Tor, the whole
// machine may send nothing out except the tor process to the given
// relays/bridges. The returned script is applied together with the main
// ruleset (one transaction); empty dst means nothing at all gets out.
type Emergencer interface {
	Emergency(torGroup engine.Group, dst []netip.Prefix) (string, error)
	// EmergencyOff is the script that removes the emergency table.
	EmergencyOff() string
	// EmergencyIntact: the emergency table is still loaded.
	EmergencyIntact() bool
}

// torDataRoot holds the tor data directories (a variable for tests).
var torDataRoot = "/var/lib/shunt/tor"

// emergencyDsts returns where the tor process of tunnel name may connect:
// its bridges, else every relay of its cached consensus. any: the bridges
// hide their destination (snowflake, meek, webtunnel), so the tor process
// (and its transport) may connect anywhere, but nothing else.
func emergencyDsts(name string, tc config.Tunnel) (dst []netip.Prefix, any bool, err error) {
	if br := tunnel.ExpandBridges(tc.Bridges); len(br) > 0 {
		dst, any = tunnel.BridgeDsts(br)
		if any {
			return []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}, true, nil
		}
		if len(dst) == 0 {
			return nil, false, errors.New("no usable bridge address")
		}
		return dst, false, nil
	}
	dst, err = tunnel.TorRelays(filepath.Join(torDataRoot, name))
	if err == nil && len(dst) == 0 {
		err = errors.New("the cached consensus lists no relays")
	}
	return dst, false, err
}

// emergencyScript adds tor-all's strict part to the ruleset and returns it
// (and "" when off). Backends without Emergencer keep the plain tor-all.
func emergencyScript(b Backend, p *Prepared, torAll string) string {
	p.EmergKey = ""
	em, ok := b.(Emergencer)
	if !ok {
		if torAll != "" {
			p.Notes = append(p.Notes, check.Note("tor.nostrict", "tor-all: this platform cannot restrict the machine to Tor relays; apps still go through Tor, but nothing stops other traffic."))
		}
		return ""
	}
	if torAll == "" {
		return em.EmergencyOff()
	}
	tc := p.Config.Tunnels[torAll]
	grp := p.Plan.DaemonGroup
	if tr := p.Plan.RouteByName("tunnel:" + torAll); tr != nil && tr.TorGroup != "" {
		p.Notes = append(p.Notes, check.Note("tor.viastrict", "tor-all: Tor tunnel \"{name}\" runs through another tunnel (via); the strict mode cannot follow that, so nothing gets out until via is removed.", "name", torAll))
		grp = engine.Group{Name: "none"}
	}
	dst, any, err := emergencyDsts(torAll, tc)
	p.EmergKey = prefixKey(dst)
	if err != nil {
		p.Notes = append(p.Notes, check.Note("tor.norelays", "tor-all: no relay list yet ({err}): nothing gets out until Tor knows its relays or bridges are set.", "err", err.Error()))
		dst = nil
	}
	if any {
		p.Notes = append(p.Notes, check.Note("tor.opaque", "tor-all: the bridges (snowflake, meek, webtunnel) hide where they connect; only the Tor process may connect, to anywhere."))
	}
	if grp.Path == "" {
		dst = nil
	}
	s, err := em.Emergency(grp, dst)
	if err != nil {
		p.Notes = append(p.Notes, check.Note("tor.strictbad", "tor-all: strict rules failed ({err}).", "err", err.Error()))
		return ""
	}
	return s
}

// emergencyDue: re-read the relay list now and then, tor refreshes its
// consensus about hourly and relays come and go.
const emergencyEvery = 20 * time.Minute

// refreshEmergency reloads when the relay list of the tor-all tunnel changed.
func (d *Daemon) refreshEmergency(self string) {
	d.mu.Lock()
	name := d.torAll
	due := name != "" && d.prep != nil && time.Since(d.emergAt) > emergencyEvery
	var tc config.Tunnel
	if due {
		d.emergAt = time.Now()
		tc = d.prep.Config.Tunnels[name]
	}
	old := d.emergKey
	d.mu.Unlock()
	if !due {
		return
	}
	dst, _, _ := emergencyDsts(name, tc)
	if key := prefixKey(dst); key != old {
		d.Log.Info("tor-all: relay list changed, reloading", "relays", len(dst))
		if err := d.reload(self); err != nil {
			d.Log.Warn("tor-all: reload", "err", err)
		}
	}
}

func prefixKey(ps []netip.Prefix) string {
	h := make([]byte, 0, len(ps)*5)
	for _, p := range ps {
		h = append(h, p.Addr().AsSlice()...)
		h = append(h, byte(p.Bits()))
	}
	return string(h)
}
