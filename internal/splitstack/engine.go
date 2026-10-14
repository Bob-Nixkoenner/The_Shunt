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
)

// DNSAddr is the DNS server the TUN announces (Android: VpnService.Builder
// .addDnsServer). Queries to it are sent to the DNS server of the route of
// the asking app.
const DNSAddr = "10.111.0.53"

type tunnelConf struct {
	Name string `json:"name"`
	Conf string `json:"conf"` // wg-quick file
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
	names := map[string]bool{}
	for _, t := range c.Tunnels {
		if t.Name == "" || names[t.Name] {
			return nil, fmt.Errorf("tunnel name %q empty or twice", t.Name)
		}
		names[t.Name] = true
	}
	check := func(r string) error {
		switch {
		case r == RouteDirect, r == RouteBlock:
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
	o       Options
	stack   *stack.Stack
	tunnels map[string]*wgTunnel
	dns     netip.Addr

	mu         sync.RWMutex
	apps       map[string]string
	def        string     // default route now (network profile applied)
	direct     netip.Addr // DNS of the direct route now
	baseDef    string     // from the config, without profile
	baseDirect netip.Addr
	rules      []rule
	networks   []networkConf
	link, ssid string // current network (SetNetwork)
	netName    string // matching profile, "" = none
	domains    domainAddrs
	filter     *blocklist.Filter
	unfiltered map[string]bool
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
	e := &Engine{o: o, tunnels: map[string]*wgTunnel{}, dns: netip.MustParseAddr(DNSAddr)}
	book, err := stats.Open(c.StatsPath)
	if err != nil {
		e.logf("traffic statistics in memory only: %v", err)
		book, _ = stats.Open("")
	}
	e.book = book
	if err := e.setRules(c); err != nil {
		return nil, err
	}
	for _, t := range c.Tunnels {
		wt, err := newWGTunnel(t.Name, t.Conf, e.resolver(), o.NewBind(), o.BindUp, c.MTU)
		if err != nil {
			e.logf("tunnel %s: %v", t.Name, err)
			wt = &wgTunnel{name: t.Name, err: err.Error()}
		}
		e.tunnels[t.Name] = wt
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
		if n, ok := strings.CutPrefix(r, tunnelPref); ok && e.tunnels[n] == nil {
			return fmt.Errorf("tunnel %q is not running, restart the VPN", n)
		}
	}
	return e.setRules(c)
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
	f, skip := e.filter, e.unfiltered[app]
	e.mu.RUnlock()
	if f == nil || skip {
		return ""
	}
	return f.Check(filterLevel, blocklist.Normalize(name))
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
	if r, ok := e.apps[app]; ok && app != "" {
		return r, false
	}
	return e.def, true
}

// NetworkChanged re-opens the WireGuard sockets after the physical network
// changed (Wi-Fi <-> mobile data): sockets of the old network do not move
// along, so tunnels would stall until the next restart.
func (e *Engine) NetworkChanged() {
	for _, t := range e.tunnels {
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
	for _, t := range e.tunnels {
		t.close()
	}
}

type tunnelStatus struct {
	Name      string        `json:"name"`
	Up        bool          `json:"up"`
	Error     string        `json:"error,omitempty"`
	Handshake int64         `json:"handshake"` // unix seconds, 0 = never
	RX        int64         `json:"rx"`
	TX        int64         `json:"tx"`
	Health    health.Report `json:"health"`
}

type status struct {
	Tunnels    []tunnelStatus `json:"tunnels"`
	Flows      int64          `json:"flows"`       // connections handled since start
	Blocked    int64          `json:"blocked"`     // of those, blocked
	DNSBlocked int64          `json:"dns_blocked"` // names answered NXDOMAIN by the filter
	Time       int64          `json:"time"`
	// Traffic per tunnel and "total": this month, last month, all.
	Traffic  map[string]stats.Summary `json:"traffic"`
	Override override.Status          `json:"override"`
	Network  string                   `json:"network"` // matching profile, "" = none
}

// Status returns the state as JSON.
func (e *Engine) Status() string {
	st := status{Flows: e.flows.Load(), Blocked: e.blocked.Load(), DNSBlocked: e.dnsBlocked.Load(), Time: time.Now().Unix(),
		Traffic: e.book.Summaries(time.Now()), Override: e.ov.Status(time.Now())}
	for _, t := range e.tunnels {
		st.Tunnels = append(st.Tunnels, t.status())
	}
	sort.Slice(st.Tunnels, func(i, j int) bool { return st.Tunnels[i].Name < st.Tunnels[j].Name }) // map order: cards would jump
	e.mu.RLock()
	st.Network = e.netName
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
