package windefense

import (
	"net/netip"
	"strings"

	"github.com/Bob-Nixkoenner/the_shunt/internal/defense"
	"github.com/Bob-Nixkoenner/the_shunt/internal/splitstack"
)

// Observer returns what the netstack calls (splitstack.Options.Observer).
// The calls come from one worker goroutine (see splitstack/observe.go), so
// the cache needs no lock. The hot path never gets here.
func (r *Runner) Observer() splitstack.Observer {
	return &obs{m: r.M, keys: map[string]netip.Addr{}, seen: &r.seen}
}

type obs struct {
	m    *defense.Manager
	seen *seen
	keys map[string]netip.Addr // program -> stand-in client address
	next uint16
}

// appKey stands in for the client address of the DNS tunnel check: the
// manager keys its tracker by client and domain, here one key per program.
func (o *obs) appKey(app string) netip.Addr {
	if a, ok := o.keys[app]; ok {
		return a
	}
	if len(o.keys) > 2000 {
		o.keys = map[string]netip.Addr{}
	}
	o.next++
	a := netip.AddrFrom4([4]byte{100, 126, byte(o.next >> 8), byte(o.next)})
	o.keys[app] = a
	return a
}

func (o *obs) DNSQuery(app, name, qtype string) {
	o.m.ObserveDNSApp(o.appKey(app), appLabel(app), name, qtype)
}

func (o *obs) DNSAnswer(name string, addrs []netip.Addr) { o.m.ObserveDNSAnswer(name, addrs) }

// appName is the file name of the program (labtun.exe, not c:\lab\labtun.exe),
// lower case; "unknown" when the owner is not known.
func appName(app string) string {
	if app == "" {
		return "unknown"
	}
	return baseName(app)
}

// baseName cuts the directory off a Windows or slash path.
func baseName(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		p = p[i+1:]
	}
	return strings.ToLower(p)
}

func (o *obs) NewConn(app string, proto int, dst netip.AddrPort) {
	a := dst.Addr().Unmap()
	if proto == 6 {
		o.seen.mark(netip.AddrPortFrom(a, dst.Port()))
		o.m.NoteConn(appName(app), dst, true)
	}
	if a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || !o.m.Watching(defense.FeatReputation) {
		return
	}
	if list, hit := o.m.Reputation().Lookup(a); hit {
		pr := "tcp"
		if proto == 17 {
			pr = "udp"
		}
		// report only; the event names the program
		o.m.Report(defense.Event{Kind: defense.KindReputation, Severity: defense.SevHigh,
			Src: a.String(), Port: int(dst.Port()), Proto: pr, Detail: "list=" + list + " app=" + appName(app)})
	}
}

func appLabel(app string) string {
	if app == "" {
		return ""
	}
	return baseName(app)
}
