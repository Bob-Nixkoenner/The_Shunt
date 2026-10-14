//go:build linux

// Package mobile is The Shunt's core for Android (bound with gomobile).
//
// Android gives a VPN app exactly one TUN interface. To still route every
// app its own way - several WireGuard tunnels at the same time, direct, or
// blocked - the TUN is terminated in a userspace network stack (gVisor) and
// every new connection is re-made by this process: through the netstack of
// the WireGuard tunnel the app's rule names, or as a plain socket (the Shunt
// app itself is excluded from its own VPN, so its sockets go out directly).
// The same model as Rethink DNS / firestack.
//
// The Kotlin side owns the configuration and the UI; it calls Start with the
// TUN file descriptor and a JSON config, and answers UID lookups
// (ConnectivityManager.getConnectionOwnerUid).
package mobile

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/blocklist"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Platform is implemented by the Android app.
type Platform interface {
	// OwnerUid returns the owner of a connection (proto 6 = TCP, 17 = UDP),
	// or -1 if unknown.
	OwnerUid(proto int, srcIP string, srcPort int, dstIP string, dstPort int) int
	Log(msg string)
}

// Route names, as in shunt.toml.
const (
	RouteDirect = "direct"
	RouteBlock  = "block"
	tunnelPref  = "tunnel:"
)

// DNSAddr is the DNS server the VPN announces (VpnService.Builder
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
	Apps      map[string]string `json:"apps"`       // UID -> route
	DirectDNS string            `json:"direct_dns"` // DNS server for the direct route
	MTU       int               `json:"mtu"`
	// DNS filter: names on these lists get NXDOMAIN, except for the
	// UIDs in Unfiltered.
	Blocklists []blocklistConf `json:"blocklists"`
	Unfiltered []int           `json:"unfiltered"`
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
	for uid, r := range c.Apps {
		if _, err := strconv.Atoi(uid); err != nil {
			return nil, fmt.Errorf("apps: %q is not a UID", uid)
		}
		if err := check(r); err != nil {
			return nil, fmt.Errorf("apps[%s]: %w", uid, err)
		}
	}
	return c, nil
}

// Engine runs while the VPN is up.
type Engine struct {
	p       Platform
	stack   *stack.Stack
	tunnels map[string]*wgTunnel
	dns     netip.Addr
	direct  netip.Addr // DNS of the direct route

	mu         sync.RWMutex
	apps       map[int]string
	def        string
	filter     *blocklist.Filter
	unfiltered map[int]bool
	flows      atomic.Int64
	blocked    atomic.Int64
	dnsBlocked atomic.Int64
	stop       sync.Once
}

// Start takes over the TUN file descriptor (it is closed by Stop).
// Tunnels that fail to come up are reported in Status; apps routed to them
// are blocked (fail closed), never sent direct.
func Start(tunFD int, configJSON string, p Platform) (*Engine, error) {
	c, err := parseConfig(configJSON)
	if err != nil {
		return nil, err
	}
	e := &Engine{p: p, tunnels: map[string]*wgTunnel{}, dns: netip.MustParseAddr(DNSAddr), direct: netip.MustParseAddr(c.DirectDNS)}
	if err := e.setRules(c); err != nil {
		return nil, err
	}
	for _, t := range c.Tunnels {
		wt, err := newWGTunnel(t.Name, t.Conf, e.direct, c.MTU)
		if err != nil {
			e.logf("tunnel %s: %v", t.Name, err)
			wt = &wgTunnel{name: t.Name, err: err.Error()}
		}
		e.tunnels[t.Name] = wt
	}
	s, err := newStack(tunFD, uint32(c.MTU), e)
	if err != nil {
		e.closeTunnels()
		return nil, err
	}
	e.stack = s
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
	for _, r := range append([]string{c.Default}, values(c.Apps)...) {
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
	apps := map[int]string{}
	for k, v := range c.Apps {
		uid, _ := strconv.Atoi(k)
		apps[uid] = v
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
	unf := map[int]bool{}
	for _, u := range c.Unfiltered {
		unf[u] = true
	}
	e.mu.Lock()
	e.apps, e.def, e.filter, e.unfiltered = apps, c.Default, filter, unf
	e.mu.Unlock()
	return nil
}

const filterLevel = "on"

func loadList(b blocklistConf) (*blocklist.List, error) {
	f, err := os.Open(b.Path)
	if err != nil {
		return nil, fmt.Errorf("blocklist %s: %w", b.Name, err)
	}
	defer f.Close()
	l, err := blocklist.Parse(b.Name, f)
	if err != nil {
		return nil, fmt.Errorf("blocklist %s: %w", b.Name, err)
	}
	return l, nil
}

// blockedName returns the list that blocks a DNS name for a UID, or "".
func (e *Engine) blockedName(uid int, name string) string {
	e.mu.RLock()
	f, skip := e.filter, e.unfiltered[uid]
	e.mu.RUnlock()
	if f == nil || skip {
		return ""
	}
	return f.Check(filterLevel, blocklist.Normalize(name))
}

// routeFor picks the route of a UID.
func (e *Engine) routeFor(uid int) string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if r, ok := e.apps[uid]; ok {
		return r
	}
	return e.def
}

// Stop ends everything; the Engine cannot be started again.
func (e *Engine) Stop() {
	e.stop.Do(func() {
		if e.stack != nil {
			e.stack.Close()
			e.stack.Wait()
		}
		e.closeTunnels()
		e.logf("stopped")
	})
}

func (e *Engine) closeTunnels() {
	for _, t := range e.tunnels {
		t.close()
	}
}

type tunnelStatus struct {
	Name      string `json:"name"`
	Up        bool   `json:"up"`
	Error     string `json:"error,omitempty"`
	Handshake int64  `json:"handshake"` // unix seconds, 0 = never
	RX        int64  `json:"rx"`
	TX        int64  `json:"tx"`
}

type status struct {
	Tunnels    []tunnelStatus `json:"tunnels"`
	Flows      int64          `json:"flows"`       // connections handled since start
	Blocked    int64          `json:"blocked"`     // of those, blocked
	DNSBlocked int64          `json:"dns_blocked"` // names answered NXDOMAIN by the filter
	Time       int64          `json:"time"`
}

// Status returns the state as JSON.
func (e *Engine) Status() string {
	st := status{Flows: e.flows.Load(), Blocked: e.blocked.Load(), DNSBlocked: e.dnsBlocked.Load(), Time: time.Now().Unix()}
	for _, t := range e.tunnels {
		st.Tunnels = append(st.Tunnels, t.status())
	}
	b, _ := json.Marshal(st)
	return string(b)
}

func (e *Engine) logf(f string, a ...any) {
	if e.p != nil {
		e.p.Log(fmt.Sprintf(f, a...))
	}
}

// CheckWireGuard validates a wg-quick file (import in the app) and returns
// a short JSON summary: addresses, DNS, endpoints.
func CheckWireGuard(conf string) (string, error) {
	c, err := parseWG(conf)
	if err != nil {
		return "", err
	}
	if len(c.Peers) == 0 {
		return "", errors.New("no [Peer] in the file")
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
