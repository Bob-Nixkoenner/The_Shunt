// Package splitstack splits the traffic of one TUN device per app across
// routes: direct, block, or one of several WireGuard tunnels at the same
// time, each with its own userspace netstack.
//
// The TUN is terminated in a gVisor network stack and every new connection
// is re-made by this process on its app's route (the model of Rethink DNS /
// firestack). The platform says which app owns a connection (Android: UID
// via ConnectivityManager.getConnectionOwnerUid; Windows: the process from
// the TCP/UDP owner tables) and how sockets reach the real network without
// looping back into the TUN (Android: the app is excluded from its own VPN;
// Windows: sockets bound to the physical interface).
//
// Used by package mobile (Android, gomobile); see docs/ANDROID.md and
// docs/WINDOWS.md.
package splitstack

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/blocklist"
	"github.com/Bob-Nixkoenner/the_shunt/internal/health"
	"github.com/Bob-Nixkoenner/the_shunt/internal/override"
	"github.com/Bob-Nixkoenner/the_shunt/internal/stats"
	"golang.zx2c4.com/wireguard/conn"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Route names, as in shunt.toml.
const (
	RouteDirect = "direct"
	RouteBlock  = "block"
	tunnelPref  = "tunnel:"
	linkPref    = "link:" // link:wifi | link:ethernet | link:mobile
)

// DNSAddr is the DNS server the TUN announces (Android: VpnService.Builder
// .addDnsServer). Queries to it are sent to the DNS server of the route of
// the asking app.
const DNSAddr = "10.111.0.53"

type tunnelConf struct {
	Name string `json:"name"`
	Type string `json:"type,omitempty"` // "wireguard" (default), "openvpn" or "tailscale"
	Conf string `json:"conf"`           // wg-quick file, .ovpn text or .ts text
	User string `json:"user,omitempty"` // OpenVPN auth-user-pass
	Pass string `json:"pass,omitempty"`
	// Via: OpenVPN only, the WireGuard tunnel that carries it (multi-hop,
	// see via.go); "" = straight over the network.
	Via string `json:"via,omitempty"`
}

type blocklistConf struct {
	Name string `json:"name"`
	Path string `json:"path"` // downloaded by the app
}

type config struct {
	Tunnels   []tunnelConf      `json:"tunnels"`
	Default   string            `json:"default"`    // route for apps without a rule
	Apps      map[string]string `json:"apps"`       // app ID (see Owner) -> route
	DirectDNS string            `json:"direct_dns"` // DNS server for the direct route
	MTU       int               `json:"mtu"`
	// OnDemand: WireGuard tunnels that no app uses are closed and made
	// again on the first connection (ondemand.go).
	OnDemand bool `json:"on_demand"`
	// DNSServers: asked after the DNS of the route itself, when that one
	// does not answer (dnslist.go); IgnoreTunnelDNS leaves the tunnel's own out.
	DNSServers      []string `json:"dns_servers"`
	IgnoreTunnelDNS bool     `json:"ignore_tunnel_dns"`
	// DNS filter: names on these lists get NXDOMAIN, except for the
	// apps in Unfiltered.
	Blocklists []blocklistConf `json:"blocklists"`
	Unfiltered []string        `json:"unfiltered"`
	// StatsPath: file for traffic totals per tunnel and month
	// (internal/stats); "" counts in memory only.
	StatsPath string `json:"stats_path"`

	// Networks: profiles per Wi-Fi/link (SetNetwork); Rules: routes by
	// destination (domain, CIDR, port), before the app rules. See rules.go.
	Networks []networkConf `json:"networks"`
	Rules    []ruleConf    `json:"rules"`

	// OpenVPN: the openvpn program (Android build, android/build-openvpn.sh)
	// and a private folder for its files. Empty: no OpenVPN tunnels.
	OpenVPN string `json:"openvpn"`
	WorkDir string `json:"work_dir"`
}

func parseConfig(js string) (*config, error) {
	c := &config{}
	if err := json.Unmarshal([]byte(js), c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if c.Default == "" {
		c.Default = RouteBlock
	}
	if c.DirectDNS == "" {
		c.DirectDNS = "1.1.1.1"
	}
	if _, err := netip.ParseAddr(c.DirectDNS); err != nil {
		return nil, fmt.Errorf("direct_dns: %w", err)
	}
	if c.MTU == 0 {
		c.MTU = 1280
	}
	if len(c.DNSServers) > maxDNSServers {
		return nil, fmt.Errorf("dns_servers: at most %d", maxDNSServers)
	}
	for _, s := range c.DNSServers {
		if _, err := netip.ParseAddr(s); err != nil {
			return nil, fmt.Errorf("dns_servers: %w", err)
		}
	}
	names := map[string]bool{}
	for i, t := range c.Tunnels {
		if t.Name == "" || names[t.Name] {
			return nil, fmt.Errorf("tunnel name %q empty or twice", t.Name)
		}
		switch t.Type {
		case "":
			c.Tunnels[i].Type = typeWireGuard
		case typeWireGuard, typeOpenVPN, typeTailscale:
		default:
			return nil, fmt.Errorf("tunnel %q: type %q (wireguard | openvpn | tailscale)", t.Name, t.Type)
		}
		names[t.Name] = true
	}
	check := func(r string) error {
		switch {
		case r == RouteDirect, r == RouteBlock:
			return nil
		case r == linkPref+"wifi", r == linkPref+"ethernet", r == linkPref+"mobile":
			return nil
		case strings.HasPrefix(r, tunnelPref) && names[strings.TrimPrefix(r, tunnelPref)]:
			return nil
		}
		return fmt.Errorf("unknown route %q", r)
	}
	if err := check(c.Default); err != nil {
		return nil, err
	}
	for app, r := range c.Apps {
		if app == "" {
			return nil, errors.New("apps: empty app ID")
		}
		if err := check(r); err != nil {
			return nil, fmt.Errorf("apps[%s]: %w", app, err)
		}
	}
	for _, n := range c.Networks {
		if n.Default != "" {
			if err := check(n.Default); err != nil {
				return nil, fmt.Errorf("network %q: %w", n.Name, err)
			}
		}
		if n.DirectDNS != "" {
			if _, err := netip.ParseAddr(n.DirectDNS); err != nil {
				return nil, fmt.Errorf("network %q: direct_dns: %w", n.Name, err)
			}
		}
		switch n.Link {
		case "", "wifi", "mobile", "ethernet":
		default:
			return nil, fmt.Errorf("network %q: link %q (wifi | mobile | ethernet)", n.Name, n.Link)
		}
	}
	if _, err := compileRules(c.Rules, check); err != nil {
		return nil, err
	}
	return c, nil
}

// Owner returns the app ID of a connection (proto 6 = TCP, 17 = UDP), or
// "" if unknown (then the default route applies).
type Owner func(proto int, src, dst netip.AddrPort) string

// Options are the platform's parts.
type Options struct {
	Link  stack.LinkEndpoint // the TUN
	Owner Owner
	Log   func(string)
	// DialDirect opens sockets of the direct route and DNS lookups of
	// WireGuard endpoints; they must not go back into the TUN. nil: net.Dialer.
	DialDirect func(ctx context.Context, network, addr string) (net.Conn, error)
	// NewBind makes the UDP socket of a WireGuard tunnel. nil: conn.NewDefaultBind.
	NewBind func() conn.Bind
	// HealthEvery is how often tunnels in use are checked (internal/health).
	// 0: 30 s.
	HealthEvery time.Duration
	// BindUp is called with a tunnel's Bind once its sockets are open
	// (Windows: conn.BindSocketToInterface to leave through the physical
	// interface). nil: nothing.
	BindUp func(conn.Bind) error
}

// Engine runs while the VPN is up.
type Engine struct {
	o        Options
	stack    *stack.Stack
	tunMu    sync.RWMutex // guards the tunnel map (slots are swapped, see ondemand.go)
	wakeMu   sync.Mutex   // one wake-up at a time
	tunnels  map[string]*wgTunnel
	mtu      int
	dns      netip.Addr
	onDemand atomic.Bool
	dnsGood  dnsGoods
	ovpnExe  string // openvpn program, "" = none
	workDir  string

	mu         sync.RWMutex
	apps       map[string]string
	def        string     // default route now (network profile applied)
	direct     netip.Addr // DNS of the direct route now
	baseDef    string     // from the config, without profile
	baseDirect netip.Addr
	rules      []rule
	// DNS servers after the route's own one, and whether the tunnels' own are left out
	dnsExtra        []netip.Addr
	ignoreTunnelDNS bool
	networks        []networkConf
	link, ssid      string // current network (SetNetwork)
	netName         string // matching profile, "" = none
	domains         domainAddrs
	filter          *blocklist.Filter
	unfiltered      map[string]bool
	// extFilter/extLevel: a filter kept up to date by the platform
	// (SetFilter), used while the config names no blocklists itself.
	extFilter  *blocklist.Filter
	extLevel   string
	recent     []blockedQuery // newest last, at most recentBlocked
	flows      atomic.Int64
	blocked    atomic.Int64
	dnsBlocked atomic.Int64
	stop       sync.Once
	ov         override.State
	actMu      sync.Mutex
	active     map[*flow][]net.Conn // running flows (see track)
	passTimer  *time.Timer
	stopHealth context.CancelFunc
	healthDone chan struct{}
	book       *stats.Book
}

// New starts the tunnels and takes over the TUN (o.Link; the platform
// closes the device itself after Stop). Tunnels that fail to come up are
// reported in Status; apps routed to them are blocked (fail closed), never
// sent direct.
func New(o Options, configJSON string) (*Engine, error) {
	c, err := parseConfig(configJSON)
	if err != nil {
		return nil, err
	}
	if o.DialDirect == nil {
		var d net.Dialer
		o.DialDirect = d.DialContext
	}
	if o.NewBind == nil {
		o.NewBind = conn.NewDefaultBind
	}
	e := &Engine{o: o, tunnels: map[string]*wgTunnel{}, mtu: c.MTU, dns: netip.MustParseAddr(DNSAddr), ovpnExe: c.OpenVPN, workDir: c.WorkDir}
	book, err := stats.Open(c.StatsPath)
	if err != nil {
		e.logf("traffic statistics in memory only: %v", err)
		book, _ = stats.Open("")
	}
	e.book = book
	if err := e.setRules(c); err != nil {
		return nil, err
	}
	// tunnels with "via" after the ones that carry them
	ordered := make([]tunnelConf, 0, len(c.Tunnels))
	for _, t := range c.Tunnels {
		if t.Via == "" {
			ordered = append(ordered, t)
		}
	}
	for _, t := range c.Tunnels {
		if t.Via != "" {
			ordered = append(ordered, t)
		}
	}
	for _, t := range ordered {
		var wt *wgTunnel
		if c.OnDemand && onDemandEligible(t, c.Tunnels) {
			if _, err := parseWG(t.Conf); err == nil { // a broken file is shown as an error now, not at the first use
				e.tunnels[t.Name] = dormantTunnel(t.Name, t.Conf)
				continue
			}
		}
		if t.Type == typeOpenVPN {
			wt, err = e.newOVPNTunnel(t, c.MTU)
		} else if t.Type == typeTailscale {
			wt, err = e.newTSTunnel(t)
		} else {
			wt, err = newWGTunnel(t.Name, t.Conf, e.resolver(), o.NewBind(), o.BindUp, c.MTU)
			if wt != nil && onDemandEligible(t, c.Tunnels) {
				wt.lazy, wt.lazyConf = true, t.Conf
				wt.use()
			}
		}
		if err != nil {
			e.logf("tunnel %s: %v", t.Name, err)
			if wt == nil {
				wt = &wgTunnel{name: t.Name}
			}
			wt.ovpnConf.Type = t.Type
			wt.tsType = t.Type == typeTailscale
			wt.err = err.Error()
		}
		e.setTunnel(t.Name, wt)
		// a new userspace tunnel starts at zero: count from the first byte
		e.book.Observe(t.Name, 0, 0, time.Now())
	}
	s, err := newStack(o.Link, e)
	if err != nil {
		e.closeTunnels()
		return nil, err
	}
	e.stack = s
	if o.HealthEvery == 0 {
		o.HealthEvery = 30 * time.Second
	}
	ctx, cancel := context.WithCancel(context.Background())
	e.stopHealth, e.healthDone = cancel, make(chan struct{})
	go e.healthLoop(ctx, o.HealthEvery)
	e.logf("started: %d tunnel(s), default %s", len(c.Tunnels), c.Default)
	return e, nil
}

// SetRules swaps default route and app rules without restarting (same JSON
// format; tunnels in it are ignored, new connections only).
func (e *Engine) SetRules(configJSON string) error {
	c, err := parseConfig(configJSON)
	if err != nil {
		return err
	}
	routes := append([]string{c.Default}, values(c.Apps)...)
	for _, n := range c.Networks {
		routes = append(routes, n.Default)
	}
	for _, r := range c.Rules {
		routes = append(routes, r.Route)
	}
	for _, r := range routes {
		if n, ok := strings.CutPrefix(r, tunnelPref); ok && e.tunnel(n) == nil {
			return fmt.Errorf("tunnel %q is not running, restart the VPN", n)
		}
	}
	if err := e.setRules(c); err != nil {
		return err
	}
	if !c.OnDemand {
		go e.wakeAll()
	}
	return nil
}

func values(m map[string]string) []string {
	var v []string
	for _, x := range m {
		v = append(v, x)
	}
	return v
}

func (e *Engine) setRules(c *config) error {
	apps := map[string]string{}
	for k, v := range c.Apps {
		apps[k] = v
	}
	var filter *blocklist.Filter
	if len(c.Blocklists) > 0 {
		var lists []*blocklist.List
		for _, b := range c.Blocklists {
			l, err := loadList(b)
			if err != nil {
				return err
			}
			lists = append(lists, l)
		}
		filter = blocklist.NewFilter(map[string][]*blocklist.List{filterLevel: lists}, nil)
	}
	unf := map[string]bool{}
	for _, u := range c.Unfiltered {
		unf[u] = true
	}
	rules, err := compileRules(c.Rules, func(string) error { return nil })
	if err != nil {
		return err
	}
	e.mu.Lock()
	e.apps, e.filter, e.unfiltered, e.rules, e.networks = apps, filter, unf, rules, c.Networks
	e.baseDef, e.baseDirect = c.Default, netip.MustParseAddr(c.DirectDNS)
	e.dnsExtra, e.ignoreTunnelDNS = nil, c.IgnoreTunnelDNS
	for _, s := range c.DNSServers {
		e.dnsExtra = append(e.dnsExtra, netip.MustParseAddr(s))
	}
	e.onDemand.Store(c.OnDemand)
	e.applyNetwork()
	e.mu.Unlock()
	return nil
}

const filterLevel = "on"

// lists caches parsed blocklists by path: SetRules runs on every rule
// change in the app, and parsing 100k names each time would stall it.
var lists struct {
	sync.Mutex
	m map[string]cachedList
}

type cachedList struct {
	mod  time.Time
	size int64
	l    *blocklist.List
}

func loadList(b blocklistConf) (*blocklist.List, error) {
	f, err := os.Open(b.Path)
	if err != nil {
		return nil, fmt.Errorf("blocklist %s: %w", b.Name, err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("blocklist %s: %w", b.Name, err)
	}
	lists.Lock()
	defer lists.Unlock()
	if c, ok := lists.m[b.Path]; ok && c.mod.Equal(st.ModTime()) && c.size == st.Size() && c.l.Name == b.Name {
		return c.l, nil
	}
	l, err := blocklist.Parse(b.Name, f)
	if err != nil {
		return nil, fmt.Errorf("blocklist %s: %w", b.Name, err)
	}
	if lists.m == nil {
		lists.m = map[string]cachedList{}
	}
	lists.m[b.Path] = cachedList{st.ModTime(), st.Size(), l}
	return l, nil
}

// blockedName returns the list that blocks a DNS name for an app, or "".
// A pass (override) lets everything through, the filter too.
func (e *Engine) blockedName(app, name string) string {
	if e.ov.Passing(time.Now()) {
		return ""
	}
	e.mu.RLock()
	f, level, skip := e.filter, filterLevel, appInSet(e.unfiltered, app)
	if f == nil {
		f, level = e.extFilter, e.extLevel
	}
	e.mu.RUnlock()
	if f == nil || skip {
		return ""
	}
	list := f.Check(level, blocklist.Normalize(name))
	if list != "" {
		e.noteBlocked(app, name, level, list)
	}
	return list
}

// SetFilter swaps the DNS filter kept by the platform (downloaded lists):
// names on the lists of level are answered NXDOMAIN. nil = no filter.
func (e *Engine) SetFilter(f *blocklist.Filter, level string) {
	e.mu.Lock()
	e.extFilter, e.extLevel = f, level
	e.mu.Unlock()
}

const recentBlocked = 50

type blockedQuery struct {
	Time  time.Time `json:"time"`
	Name  string    `json:"name"`
	Level string    `json:"level"`
	List  string    `json:"list"`
	Route string    `json:"route"` // the app that asked
}

func (e *Engine) noteBlocked(app, name, level, list string) {
	q := blockedQuery{Time: time.Now(), Name: strings.TrimSuffix(strings.ToLower(name), "."), Level: level, List: list, Route: app}
	e.mu.Lock()
	if len(e.recent) >= recentBlocked {
		e.recent = append(e.recent[:0], e.recent[1:]...)
	}
	e.recent = append(e.recent, q)
	e.mu.Unlock()
}

// routeFor picks the route of a connection: destination rules, then the
// app's rule, then the default (of the network profile).
// byDefault: the route is the default, so it changes with the network.
func (e *Engine) routeFor(app string, proto int, dst netip.AddrPort, isDNS bool) (route string, byDefault bool) {
	if !isDNS {
		if r, _ := e.ruleRoute(app, proto, dst); r != "" {
			return r, false
		}
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	if r, ok := appRoute(e.apps, app); ok && app != "" {
		return r, false
	}
	return e.def, true
}

// NetworkChanged re-opens the WireGuard sockets after the physical network
// changed (Wi-Fi <-> mobile data): sockets of the old network do not move
// along, so tunnels would stall until the next restart.
func (e *Engine) NetworkChanged() {
	for _, t := range e.tunnels {
		if t.isOVPN() {
			if ot := t.ovpnTunnel(); ot != nil {
				ot.NetworkChanged()
			}
			continue
		}
		if t.dev == nil {
			continue
		}
		if err := t.dev.BindUpdate(); err != nil {
			e.logf("tunnel %s: rebind: %v", t.name, err)
			continue
		}
		if e.o.BindUp != nil {
			if err := e.o.BindUp(t.dev.Bind()); err != nil {
				e.logf("tunnel %s: %v", t.name, err)
			}
		}
	}
}

// SetPanic blocks everything at once, running connections included.
func (e *Engine) SetPanic(on bool) {
	e.ov.SetPanic(on)
	if on {
		n := e.cut(func(*flow) bool { return true })
		e.logf("panic: everything blocked, %d connections cut", n)
	} else {
		e.logf("panic lifted")
	}
}

// Pass lets everything through (direct, no tunnels, no blocks, no DNS
// filter) for d, clamped to 1..60 minutes; d <= 0 ends it. When it ends,
// connections opened because of it are cut, so nothing keeps running
// unprotected. Returns the end (zero: ended).
func (e *Engine) Pass(d time.Duration) time.Time {
	now := time.Now()
	until := e.ov.Pass(d, now)
	e.actMu.Lock()
	if e.passTimer != nil {
		e.passTimer.Stop()
	}
	if !until.IsZero() {
		e.passTimer = time.AfterFunc(until.Sub(now), e.endPass)
	}
	e.actMu.Unlock()
	if until.IsZero() {
		e.endPass()
	} else {
		e.logf("pass: everything direct until %s", until.Format("15:04:05"))
	}
	return until
}

func (e *Engine) endPass() {
	if e.ov.Passing(time.Now()) {
		return // extended meanwhile
	}
	n := e.cut(func(f *flow) bool { return f.pass })
	e.logf("pass ended, %d direct connections cut", n)
}

// ResetStats deletes the traffic totals.
func (e *Engine) ResetStats() error { return e.book.Reset() }

// Stop ends everything; the Engine cannot be started again.
func (e *Engine) Stop() {
	e.stop.Do(func() {
		if e.stopHealth != nil {
			e.stopHealth()
			<-e.healthDone
		}
		e.actMu.Lock()
		if e.passTimer != nil {
			e.passTimer.Stop()
		}
		e.actMu.Unlock()
		if e.stack != nil {
			e.stack.Close()
			e.stack.Wait()
		}
		e.closeTunnels()
		if err := e.book.Close(); err != nil {
			e.logf("traffic statistics: %v", err)
		}
		e.logf("stopped")
	})
}

func (e *Engine) closeTunnels() {
	for _, t := range e.allTunnels() {
		t.close()
	}
}

type tunnelStatus struct {
	Name      string        `json:"name"`
	Type      string        `json:"type"` // wireguard | openvpn | tailscale
	Via       string        `json:"via,omitempty"`
	Up        bool          `json:"up"`
	Idle      bool          `json:"idle,omitempty"` // asleep (on demand): made on the first connection
	Error     string        `json:"error,omitempty"`
	Handshake int64         `json:"handshake"` // unix seconds, 0 = never
	RX        int64         `json:"rx"`
	TX        int64         `json:"tx"`
	Health    health.Report `json:"health"`
}

type status struct {
	Tunnels    []tunnelStatus `json:"tunnels"`
	Flows      int64          `json:"flows"`                // connections handled since start
	Blocked    int64          `json:"blocked"`              // of those, blocked
	DNSBlocked int64          `json:"dns_blocked"`          // names answered NXDOMAIN by the filter
	DNSRecent  []blockedQuery `json:"dns_recent,omitempty"` // the last ones, newest first
	Time       int64          `json:"time"`
	// Traffic per tunnel and "total": this month, last month, all.
	Traffic  map[string]stats.Summary `json:"traffic"`
	Override override.Status          `json:"override"`
	Network  string                   `json:"network"` // matching profile, "" = none
}

// History returns the traffic and DNS-block history for a range ("1h", "24h",
// "7d", "30d") as JSON (stats.History).
func (e *Engine) History(rng string) string {
	b, _ := json.Marshal(e.book.History(rng, time.Now()))
	return string(b)
}

// Status returns the state as JSON.
func (e *Engine) Status() string {
	st := status{Flows: e.flows.Load(), Blocked: e.blocked.Load(), DNSBlocked: e.dnsBlocked.Load(), Time: time.Now().Unix(),
		Traffic: e.book.Summaries(time.Now()), Override: e.ov.Status(time.Now())}
	for _, t := range e.allTunnels() {
		st.Tunnels = append(st.Tunnels, t.status())
	}
	sort.Slice(st.Tunnels, func(i, j int) bool { return st.Tunnels[i].Name < st.Tunnels[j].Name }) // map order: cards would jump
	e.mu.RLock()
	st.Network = e.netName
	for i := len(e.recent) - 1; i >= 0; i-- {
		st.DNSRecent = append(st.DNSRecent, e.recent[i])
	}
	e.mu.RUnlock()
	b, _ := json.Marshal(st)
	return string(b)
}

func (e *Engine) logf(f string, a ...any) {
	if e.o.Log != nil {
		e.o.Log(fmt.Sprintf(f, a...))
	}
}

// CheckWireGuard validates a wg-quick file (import in an app) and returns
// a short JSON summary: addresses, DNS, endpoints.
func CheckWireGuard(conf string) (string, error) {
	c, err := parseWG(conf)
	if err != nil {
		return "", err
	}
	if len(c.Peers) == 0 {
		return "", errors.New("no [Peer] in the file")
	}
	if len(c.Addresses) == 0 {
		return "", errors.New("no Address in [Interface]")
	}
	sum := struct {
		Addresses []string `json:"addresses"`
		DNS       []string `json:"dns"`
		Endpoints []string `json:"endpoints"`
	}{DNS: c.DNS}
	for _, a := range c.Addresses {
		sum.Addresses = append(sum.Addresses, a.String())
	}
	for _, p := range c.Peers {
		sum.Endpoints = append(sum.Endpoints, p.Endpoint)
	}
	b, _ := json.Marshal(sum)
	return string(b), nil
}

// MTU returns the TUN MTU of a config (for the platform's link endpoint).
func MTU(configJSON string) (int, error) {
	c, err := parseConfig(configJSON)
	if err != nil {
		return 0, err
	}
	return c.MTU, nil
}
