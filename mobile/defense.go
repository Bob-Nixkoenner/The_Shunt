//go:build linux

package mobile

import (
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/Bob-Nixkoenner/the_shunt/internal/defense"
	"github.com/Bob-Nixkoenner/the_shunt/internal/splitstack"
)

// The defense on Android is a watcher, not a trap: no root, no decoy
// listeners, no packet sniffing, no firewall. It watches what the netstack
// sees anyway (DNS, new connections per app), compares destinations with the
// reputation lists and tells the user. Nothing is blocked, nothing leaves
// the phone. See docs/DEFENSE.md, "Windows and Android".

// androidFeatures are the features that work here; everything else (decoys,
// scan and brute-force detection, ARP/DHCP/RA, TLS check, evil twin,
// interface changes, rebind) stays off and cannot be switched on.
var androidFeatures = []string{defense.FeatDNSTunnel, defense.FeatReputation, defense.FeatFirstSeen, defense.FeatBeacon}

func androidConfig() defense.Config {
	cfg := defense.DefaultConfig()
	cfg.Enabled = false
	for _, n := range defense.AllFeatures {
		cfg.Features[n] = defense.Feature{}
	}
	for _, n := range androidFeatures {
		cfg.Features[n] = defense.Feature{Watch: true}
	}
	return cfg
}

func noListen(int) (net.Listener, error) { return nil, errors.New("no listeners on Android") }

// defObs feeds the manager from the netstack's observer worker (one
// goroutine, so the caches need no lock). The hot path never gets here.
type defObs struct {
	m     *defense.Manager
	p     Platform
	names map[string]string // uid -> package name
}

func (d *defObs) app(uid string) string {
	if uid == "" {
		return ""
	}
	if n, ok := d.names[uid]; ok {
		return n
	}
	n := ""
	if i, err := strconv.Atoi(uid); err == nil && d.p != nil {
		n = d.p.AppName(i)
	}
	if n == "" {
		n = "uid-" + uid
	}
	if len(d.names) > 2000 {
		d.names = map[string]string{}
	}
	d.names[uid] = n
	return n
}

// appKey stands in for the client address of the DNS tunnel check: one key
// per app (the manager keys its tracker by client and domain).
func appKey(uid string) netip.Addr {
	i, _ := strconv.Atoi(uid)
	return netip.AddrFrom4([4]byte{100, 127, byte(i >> 8), byte(i)})
}

func (d *defObs) DNSQuery(app, name, qtype string) { d.m.ObserveDNS(appKey(app), name, qtype) }

func (d *defObs) DNSAnswer(name string, addrs []netip.Addr) { d.m.ObserveDNSAnswer(name, addrs) }

func (d *defObs) NewConn(app string, proto int, dst netip.AddrPort) {
	a := dst.Addr().Unmap()
	if proto == 6 {
		d.m.NoteConn(d.app(app), dst, true)
	}
	if !a.IsPrivate() && !a.IsLoopback() && !a.IsLinkLocalUnicast() && d.m.Watching(defense.FeatReputation) {
		if list, hit := d.m.Reputation().Lookup(a); hit {
			pr := "tcp"
			if proto == 17 {
				pr = "udp"
			}
			// report only (Android never blocks); the event names the app
			d.m.Report(defense.Event{Kind: defense.KindReputation, Severity: defense.SevHigh,
				Src: a.String(), Port: int(dst.Port()), Proto: pr, Detail: "list=" + list + " app=" + d.app(app)})
		}
	}
}

type defenseState struct {
	m   *defense.Manager
	dir string

	mu  sync.Mutex
	cfg defense.Config
	rep *defense.Updater
}

func newDefense(dir string, p Platform) (*defenseState, *defObs) {
	opts := []defense.Option{defense.WithListen(noListen)}
	if dir != "" {
		opts = append(opts, defense.WithFirstSeenFile(filepath.Join(dir, "first-seen.json")))
	}
	m := defense.NewManager(nil, opts...)
	m.Configure(androidConfig())
	st := &defenseState{m: m, dir: dir, cfg: androidConfig()}
	st.rep = &defense.Updater{Rep: m.Reputation(), Dir: dir}
	return st, &defObs{m: m, p: p, names: map[string]string{}}
}

type defenseInput struct {
	Enabled           bool                       `json:"enabled"`
	Features          map[string]defense.Feature `json:"features"`
	ReputationSources []string                   `json:"reputation_sources"`
	ReputationOff     []string                   `json:"reputation_off"`
}

// configure applies the user's switches; features that do not exist on
// Android and every Block switch are ignored.
func (d *defenseState) configure(in defenseInput) {
	cfg := androidConfig()
	cfg.Enabled = in.Enabled
	for _, n := range androidFeatures {
		if f, ok := in.Features[n]; ok {
			cfg.Features[n] = defense.Feature{Watch: f.Watch}
		}
	}
	cfg.ReputationSources = in.ReputationSources
	cfg.ReputationOff = in.ReputationOff
	d.mu.Lock()
	d.cfg = cfg
	d.mu.Unlock()
	d.m.Configure(cfg)
	d.reload()
}

func (d *defenseState) sources() []defense.Source {
	d.mu.Lock()
	cfg := d.cfg
	d.mu.Unlock()
	if !cfg.Enabled || !cfg.Features[defense.FeatReputation].Watch {
		return nil
	}
	return defense.SourcesFor(cfg.ReputationSources, cfg.ReputationOff)
}

func (d *defenseState) reload() int {
	if d.dir == "" {
		return 0
	}
	return d.rep.LoadCache(d.sources())
}

// DefenseConfig applies the defense settings (JSON: {"enabled":bool,
// "features":{"beacon":{"watch":true},...}, "reputation_sources":[],
// "reputation_off":[]}). Only dns_tunnel, reputation, first_seen and beacon
// exist on Android; Block switches are ignored. Off by default.
func (e *Engine) DefenseConfig(configJSON string) error {
	var in defenseInput
	if err := json.Unmarshal([]byte(configJSON), &in); err != nil {
		return err
	}
	e.def.configure(in)
	return nil
}

// DefenseNetwork tells the defense which network class applies ("unknown",
// "unsafe" or "safe"; the old "public", "trusted" and "managed" still work;
// anything else = unknown). key identifies the network
// locally (the app passes a hash, never the name); it is never logged.
func (e *Engine) DefenseNetwork(key, class string) { e.def.m.SetNetwork(key, defense.Class(class)) }

// DefenseEvents returns the events with Seq > since as JSON
// ({"events":[...],"last_seq":N}, at most 200, oldest first).
func (e *Engine) DefenseEvents(since int64) string {
	if since < 0 {
		since = 0
	}
	b, _ := json.Marshal(e.def.m.Events(uint64(since)))
	return string(b)
}

// DefenseSources lists the reputation lists the app should download (JSON:
// [{"name","url","file"}], file = name inside the cache directory) and then
// announce with DefenseReload. Empty while the defense or its reputation
// check is off.
func (e *Engine) DefenseSources() string {
	type src struct {
		Name string `json:"name"`
		URL  string `json:"url"`
		File string `json:"file"`
	}
	out := []src{}
	for _, s := range e.def.sources() {
		out = append(out, src{s.Name, s.URL, filepath.Base(defense.CacheFile("", s))})
	}
	b, _ := json.Marshal(out)
	return string(b)
}

// DefenseReload loads the downloaded lists from the cache directory and
// returns how many were loaded.
func (e *Engine) DefenseReload() int { return e.def.reload() }

// defenseStatus is the "defense" object of Status().
type defenseStatus struct {
	Enabled bool           `json:"enabled"`
	Heat    int            `json:"heat"`
	Level   defense.Level  `json:"level"`
	Class   defense.Class  `json:"class"`
	Exposed bool           `json:"exposed"`
	LastSeq uint64         `json:"last_seq"`
	Dropped int64          `json:"dropped"`
	Sources []sourceStatus `json:"sources,omitempty"`
}

type sourceStatus struct {
	Name    string `json:"name"`
	Entries int    `json:"entries"`
	Expired bool   `json:"expired,omitempty"`
	Error   string `json:"error,omitempty"`
}

func (e *Engine) defenseJSON() string {
	st := e.def.m.Status()
	ds := defenseStatus{Enabled: st.Enabled, Heat: st.Heat, Level: st.Level, Class: st.Class, Exposed: st.Exposed.Any(),
		LastSeq: st.LastSeq}
	if e.e != nil {
		ds.Dropped = e.e.ObserveDropped()
	}
	for _, s := range st.Sources {
		if s.On {
			ds.Sources = append(ds.Sources, sourceStatus{s.Name, s.Entries, s.Expired, s.Error})
		}
	}
	b, _ := json.Marshal(ds)
	return string(b)
}

var _ splitstack.Observer = (*defObs)(nil)
