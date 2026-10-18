// Package daemon wires config, engine and the Linux backend together and
// serves the API.
package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/api"
	"github.com/Bob-Nixkoenner/the_shunt/internal/appwatch"
	"github.com/Bob-Nixkoenner/the_shunt/internal/blocklist"
	"github.com/Bob-Nixkoenner/the_shunt/internal/captive"
	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/Bob-Nixkoenner/the_shunt/internal/dnsproxy"
	"github.com/Bob-Nixkoenner/the_shunt/internal/engine"
	"github.com/Bob-Nixkoenner/the_shunt/internal/firewall"
	"github.com/Bob-Nixkoenner/the_shunt/internal/health"
	"github.com/Bob-Nixkoenner/the_shunt/internal/links"
	"github.com/Bob-Nixkoenner/the_shunt/internal/netdetect"
	"github.com/Bob-Nixkoenner/the_shunt/internal/override"
	"github.com/Bob-Nixkoenner/the_shunt/internal/ovpnconf"
	"github.com/Bob-Nixkoenner/the_shunt/internal/routing"
	"github.com/Bob-Nixkoenner/the_shunt/internal/stats"
	"github.com/Bob-Nixkoenner/the_shunt/internal/tsconf"
	"github.com/Bob-Nixkoenner/the_shunt/internal/tunnel"
	"github.com/Bob-Nixkoenner/the_shunt/internal/wgconf"
)

// Daemon is the running shuntd.
type Daemon struct {
	ConfigPath string
	Log        *slog.Logger
	Version    string // build version, reported in the status
	// Backend enforces plans on this platform (nil: DefaultBackend).
	Backend Backend

	mu        sync.Mutex
	cfg       *config.Config
	plan      *engine.Plan
	prep      *Prepared
	cg        firewall.CGroups
	tunnels   map[string]tunnel.Device
	specHash  map[string]string
	tunErrors map[string]string
	panic     bool
	proxy     *dnsproxy.Proxy
	filter    *blocklist.Manager
	watcher   AppWatcher
	saveMu    sync.Mutex // serializes config writes
	dnsUps    dnsproxy.RouteUpstreams
	// pushed holds the DNS servers OpenVPN servers pushed ([]netip.Addr per
	// tunnel name); read by the DNS proxy without d.mu.
	pushed sync.Map
	// tunEvents: an OpenVPN tunnel connected or disconnected.
	tunEvents chan struct{}
	netInfo   netdetect.Info
	// links: the connected Wi-Fi/cable/mobile interfaces (link routes);
	// linkDNS holds their DNS servers ([]netip.Addr per kind), read by
	// the DNS proxy without d.mu.
	links    links.State
	linkDNS  sync.Map
	netRetry bool // a profile switch failed: retry on the next network tick
	// routeSoft: routes that could not be copied yet (retried every tick)
	routeSoft string
	restart   chan struct{}

	fw *firewall.Manager

	captive, captiveURL string
	captiveAt           time.Time // last probe
	probing             bool

	ov      override.State // timed pass (panic stays in the backend)
	passing bool           // the plan in place was built for a pass

	health     map[string]*health.Monitor // per tunnel, see health.go
	healthBusy bool
	book       *stats.Book // traffic totals, opened by checkHealth
}

// ErrRestart: Run ended because a restart was requested through the API;
// shuntd exits non-zero so systemd (Restart=on-failure) starts it again.
var ErrRestart = errors.New("restart requested")

// Prepared is the result of loading config and tunnel files.
type Prepared struct {
	Config *config.Config
	Plan   *engine.Plan
	Confs  map[string]*wgconf.Config
	OVPN   map[string]*ovpnconf.Config
	TS     map[string]*tsconf.Config
	// AuthFiles: absolute username/password file per OpenVPN tunnel.
	AuthFiles map[string]string
	Hashes    map[string]string
	Ruleset   string
	// DNS upstreams per route name, and problems worth telling the user.
	DNSUpstreams map[string][]config.UpstreamSpec
	// DirectSystem: the direct route uses the system resolvers, re-read
	// whenever resolv.conf changes (not in DNSUpstreams).
	DirectSystem bool
	Warnings     []string
	// Network is the matched [[network]] ("" = none: daemon.default_route).
	Network string
}

// Prepare loads everything and compiles the plan without touching the system.
func Prepare(path, cgroupRoot string) (*Prepared, error) {
	return PrepareOn(path, cgroupRoot, Env{Links: links.Current(), Backend: DefaultBackend()})
}

// Env is what a config is prepared for.
type Env struct {
	// Net is the network we are on: a matching [[network]] replaces the
	// default route (nil: none).
	Net *netdetect.Info
	// Links are the connected Wi-Fi/cable/mobile interfaces (link routes).
	Links links.State
	// Backend renders the plan into the platform's ruleset.
	Backend Backend
	// Pass: a timed pass runs (internal/override): every route is direct.
	Pass bool
}

// PrepareOn is Prepare for the environment env.
func PrepareOn(path, cgroupRoot string, env Env) (*Prepared, error) {
	net, ls := env.Net, env.Links
	c, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	if c.Daemon.CgroupRoot != "" {
		cgroupRoot = c.Daemon.CgroupRoot
	}
	p := &Prepared{Config: c, Confs: map[string]*wgconf.Config{}, OVPN: map[string]*ovpnconf.Config{}, TS: map[string]*tsconf.Config{}, AuthFiles: map[string]string{}, Hashes: map[string]string{}}
	infos := map[string]engine.TunnelInfo{}
	abs := func(f string) string {
		if !filepath.IsAbs(f) {
			f = filepath.Join(filepath.Dir(path), f)
		}
		return f
	}
	for name, t := range c.Tunnels {
		cp := abs(t.Config)
		if err := checkSecretFile(cp); err != nil {
			return nil, fmt.Errorf("tunnel %q: %w", name, err)
		}
		raw, err := os.ReadFile(cp)
		if err != nil {
			return nil, fmt.Errorf("tunnel %q: %w", name, err)
		}
		hash := fmt.Sprintf("%x|%s|%s|%s", sha256.Sum256(raw), t.Driver, t.Interface, t.Via)
		if t.IsTailscale() {
			tc, err := tsconf.ParseFile(cp)
			if err != nil {
				return nil, fmt.Errorf("tunnel %q: %w", name, err)
			}
			_, peer := tunnel.TailscaleAddrs(name)
			p.TS[name] = tc
			p.Hashes[name] = hash
			// IPv6 stays blocked: the veth carries IPv4 only.
			infos[name] = engine.TunnelInfo{Iface: t.Interface, HasV4: true, AllowedIPs: tc.Prefixes(), Gateway: peer, Forward: true}
			continue
		}
		if t.IsOpenVPN() {
			oc, err := ovpnconf.ParseFile(cp)
			if err != nil {
				return nil, fmt.Errorf("tunnel %q: %w", name, err)
			}
			if t.Auth != "" {
				af := abs(t.Auth)
				if err := checkSecretFile(af); err != nil {
					return nil, fmt.Errorf("tunnel %q: %w", name, err)
				}
				ab, err := os.ReadFile(af)
				if err != nil {
					return nil, fmt.Errorf("tunnel %q: %w", name, err)
				}
				p.AuthFiles[name] = af
				hash += fmt.Sprintf("|%x", sha256.Sum256(ab))
			} else if oc.NeedsAuth {
				return nil, fmt.Errorf("tunnel %q: the server wants a username and password: auth = \"<file>\" (username and password on two lines, mode 600)", name)
			}
			for _, f := range oc.Files {
				if b, err := os.ReadFile(f); err == nil {
					hash += fmt.Sprintf("|%x", sha256.Sum256(b))
				}
			}
			p.OVPN[name] = oc
			p.Hashes[name] = hash
			// Addresses come from the server; routing checks which
			// families the interface really has.
			infos[name] = engine.TunnelInfo{Iface: t.Interface, HasV4: true, HasV6: true,
				AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}}
			continue
		}
		wc, err := wgconf.ParseFile(cp)
		if err != nil {
			return nil, fmt.Errorf("tunnel %q: %w", name, err)
		}
		p.Confs[name] = wc
		p.Hashes[name] = hash
		ti := engine.TunnelInfo{Iface: t.Interface, HasV4: wc.HasIPv4(), HasV6: wc.HasIPv6()}
		for _, peer := range wc.Peers {
			ti.AllowedIPs = append(ti.AllowedIPs, peer.AllowedIPs...)
		}
		infos[name] = ti
	}
	eff := c
	if net != nil {
		if n := c.MatchNetwork(net.SSID, net.GatewayMAC); n != nil {
			cc := *c
			cc.Daemon.DefaultRoute = n.DefaultRoute
			switch n.DNSDirect {
			case "":
			case config.DNSSystem:
				cc.DNS.Direct = ""
			default:
				cc.DNS.Direct = n.DNSDirect
			}
			eff, p.Network = &cc, n.Name
		}
	}
	if env.Pass {
		// everything direct: default, network profile and every rule (block
		// too) - for a few minutes only, see Daemon.pass
		cc := *eff
		cc.Daemon.DefaultRoute = "direct"
		cc.Rules = append([]config.Rule(nil), eff.Rules...)
		for i := range cc.Rules {
			if cc.Rules[i].Route != "" {
				cc.Rules[i].Route = "direct"
			}
		}
		eff = &cc
		p.Warnings = append(p.Warnings, "pass: everything goes direct, past tunnels and blocks, until it ends")
	}
	ifaces := map[string]string{}
	for k, l := range ls {
		ifaces[k] = l.Name
	}
	p.Plan, err = engine.CompileOn(eff, cgroupRoot, infos, p.Network, ifaces)
	if err != nil {
		return nil, err
	}
	for _, r := range usedLinks(eff, p.Plan) {
		if ifaces[r] == "" {
			p.Warnings = append(p.Warnings, fmt.Sprintf("route link:%s is used, but no %s connection is up: its traffic is blocked until it is", r, linkLabel(r)))
		}
	}
	if env.Backend == nil {
		return nil, errors.New("no backend for this platform")
	}
	p.Ruleset, err = env.Backend.Render(p.Plan)
	if err != nil {
		return nil, err
	}
	if p.Plan.DNS {
		p.prepareDNS(eff)
	} else {
		p.Warnings = append(p.Warnings, "DNS routing is disabled: DNS queries leak past the tunnels")
	}
	return p, nil
}

// prepareDNS works on c, the config in effect (a network profile may
// change dns.direct).
func (p *Prepared) prepareDNS(c *config.Config) {
	p.DNSUpstreams = map[string][]config.UpstreamSpec{}
	if c.DNS.Direct != "" {
		u, _ := config.ParseUpstream(c.DNS.Upstream[c.DNS.Direct]) // validated
		p.DNSUpstreams["direct"] = []config.UpstreamSpec{u}
	} else {
		p.DirectSystem = true
	}
	for name, t := range c.Tunnels {
		route := "tunnel:" + name
		if t.DNS != "" {
			u, _ := config.ParseUpstream(c.DNS.Upstream[t.DNS])
			p.DNSUpstreams[route] = []config.UpstreamSpec{u}
			continue
		}
		if t.IsOpenVPN() {
			continue // whatever the server pushes (see Daemon.upstreams)
		}
		if t.IsTailscale() {
			// tailscaled's resolver: MagicDNS names, the tailnet's nameservers
			p.DNSUpstreams[route] = []config.UpstreamSpec{{Proto: "udp", Addr: netip.AddrPortFrom(tunnel.TailscaleDNS, 53)}}
			continue
		}
		for _, d := range p.Confs[name].DNS {
			if a, err := netip.ParseAddr(d); err == nil {
				p.DNSUpstreams[route] = append(p.DNSUpstreams[route], config.UpstreamSpec{Proto: "udp", Addr: netip.AddrPortFrom(a, 53)})
			}
		}
		if len(p.DNSUpstreams[route]) == 0 {
			p.Warnings = append(p.Warnings, fmt.Sprintf("tunnel %q has no DNS server (DNS= in its config or dns = \"<upstream>\"): its apps cannot resolve names", name))
		}
	}
	if d := c.Filter().Duplicates(); len(d) > 0 { // harmless: every list is loaded once
		p.Warnings = append(p.Warnings, fmt.Sprintf("dns_filter: %d redundant list entries (e.g. %s); Configure → DNS filter → Tidy lists removes them", len(d), d[0]))
	}
	// Domain rules trust the DNS server of their route: on a foreign network a
	// plain-DNS "direct" resolver could answer with any IP and so pull other
	// traffic out of a tunnel. Encrypted upstreams can't be tampered with.
	directPlain := c.DNS.Direct == ""
	if !directPlain {
		u, _ := config.ParseUpstream(c.DNS.Upstream[c.DNS.Direct])
		directPlain = u.Proto == "udp" || u.Proto == "tcp"
	}
	for _, r := range p.Plan.DomainRules() {
		if r.Route.Kind == config.RouteDirect && directPlain && len(c.Tunnels) > 0 {
			p.Warnings = append(p.Warnings, fmt.Sprintf("rule %q routes domains to direct using plain DNS: a hostile network could answer with other IPs and pull that traffic out of the tunnel. Use an encrypted dns.direct (tls:// or https://) when travelling", r.Name))
			break
		}
	}
	if nsswitchUsesResolved() {
		p.Warnings = append(p.Warnings, "/etc/nsswitch.conf uses 'resolve' (systemd-resolved via varlink): those lookups bypass per-route DNS. Fix: sudo shuntd fix-nsswitch")
	}
}

// nsswitchUsesResolved reports whether glibc asks systemd-resolved directly
// (nss-resolve) instead of through port 53.
func nsswitchUsesResolved() bool {
	b, err := os.ReadFile("/etc/nsswitch.conf")
	if err != nil {
		return false
	}
	for _, l := range strings.Split(string(b), "\n") {
		if f := strings.Fields(l); len(f) > 0 && f[0] == "hosts:" {
			for _, x := range f[1:] {
				if x == "resolve" {
					return true
				}
			}
		}
	}
	return false
}

func (d *Daemon) upstreams(p *Prepared) dnsproxy.RouteUpstreams {
	ups := dnsproxy.RouteUpstreams{}
	if p.DirectSystem {
		ups["direct"] = []dnsproxy.Upstream{dnsproxy.NewSystemUpstream(p.Plan.RouteByName("direct").Mark)}
	}
	for name, t := range p.Config.Tunnels {
		if t.IsOpenVPN() && t.DNS == "" {
			route := "tunnel:" + name
			ups[route] = []dnsproxy.Upstream{dnsproxy.NewPushedUpstream(p.Plan.RouteByName(route).Mark, func() []netip.Addr {
				v, _ := d.pushed.Load(name)
				a, _ := v.([]netip.Addr)
				return a
			})}
		}
	}
	if p.Plan.Captive != nil {
		// the login browser: the network's own resolvers (DHCP), never
		// dns.direct – login pages often only resolve there
		ups[dnsproxy.CaptiveUpstreams] = []dnsproxy.Upstream{dnsproxy.NewSystemUpstream(p.Plan.Captive.Mark)}
	}
	for _, r := range p.Plan.Routes {
		if r.Kind != config.RouteLink {
			continue
		}
		if direct, ok := p.DNSUpstreams["direct"]; ok {
			// an own dns.direct (DoT/DoH) is used on every connection
			for _, s := range direct {
				ups[r.String()] = append(ups[r.String()], dnsproxy.NewUpstream(s, r.Mark))
			}
			continue
		}
		kind := r.Link
		ups[r.String()] = []dnsproxy.Upstream{dnsproxy.NewLinkUpstream(r.Mark, func() []netip.Addr {
			v, _ := d.linkDNS.Load(kind)
			a, _ := v.([]netip.Addr)
			return a
		})}
	}
	for route, specs := range p.DNSUpstreams {
		r := p.Plan.RouteByName(route)
		for _, s := range specs {
			ups[route] = append(ups[route], dnsproxy.NewUpstream(s, r.Mark))
		}
	}
	return ups
}

// checkSecretFile refuses private keys that other users can read.
func checkSecretFile(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s is accessible by group/others (mode %o), chmod 600 it", path, st.Mode().Perm())
	}
	return nil
}

// Run starts the daemon and blocks until ctx is cancelled.
func (d *Daemon) Run(ctx context.Context) error {
	if d.Backend == nil {
		d.Backend = DefaultBackend()
	}
	if d.Backend == nil {
		return errors.New("the shunt has no backend for this platform yet")
	}
	self, err := d.Backend.Init()
	if err != nil {
		return err
	}
	d.cg = d.Backend.Groups()
	d.tunnels = map[string]tunnel.Device{}
	d.tunEvents = make(chan struct{}, 1)
	d.restart = make(chan struct{}, 1)
	d.specHash = map[string]string{}
	d.tunErrors = map[string]string{}
	d.netInfo = netdetect.Current()
	d.setLinks(links.Current())
	go d.probeCaptive()
	d.filter = &blocklist.Manager{Dir: d.filterDir(), Log: d.Log, Client: d.downloadClient,
		OnChange: func(f *blocklist.Filter) { d.proxy.SetFilter(f) }}

	if err := d.reload(self); err != nil {
		return err
	}
	go d.filter.Run(ctx)
	// The plan is in place: lift the boot lockdown if it was set.
	if err := d.Backend.LiftLockdown(); err != nil {
		d.Log.Warn("could not remove lockdown table", "err", err)
	}

	ln, err := d.listen()
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           d.routes(),
		ConnContext:       connContext,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       time.Minute,
	}
	go func() { _ = srv.Serve(ln) }()
	d.Log.Info("shuntd running", "socket", d.cfg.Daemon.Socket)

	stopWatch := make(chan struct{})
	defer close(stopWatch)
	go d.watcher.Run(stopWatch)
	go func() {
		if err := d.Backend.WatchHeld(ctx, d.fw.Seen); err != nil {
			d.Log.Warn("app firewall: cannot read the log of waiting programs (they stay blocked without a question)", "err", err)
		}
	}()
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				d.fw.Tick(now)
			}
		}
	}()

	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	netTick := time.NewTicker(5 * time.Second)
	defer netTick.Stop()
	hup := make(chan os.Signal, 1)
	notifyHUP(hup)
	for {
		select {
		case <-ctx.Done():
			_ = srv.Close()
			d.shutdown()
			return nil
		case <-d.restart:
			time.Sleep(200 * time.Millisecond) // let the API answer go out
			_ = srv.Close()
			d.shutdown()
			return ErrRestart
		case <-hup:
			if err := d.reload(self); err != nil {
				d.Log.Error("reload failed, keeping previous state", "err", err)
			}
		case <-tick.C:
			d.watchdog()
			go d.checkHealth()
		case <-d.tunEvents:
			d.tunnelChanged()
		case <-netTick.C:
			d.endPassIfDue(self)
			d.checkNetwork()
			d.mu.Lock()
			if d.routeSoft != "" && d.prep != nil {
				if err := d.syncRoutes(d.plan, d.ifaceUp(d.prep)); err != nil {
					d.Log.Warn("routing sync", "err", err)
				}
			}
			d.mu.Unlock()
			d.mu.Lock()
			again := d.captive != captive.Online && time.Since(d.captiveAt) > 15*time.Second
			d.mu.Unlock()
			if again { // waiting for the user to log in
				go d.probeCaptive()
			}
		}
	}
}

// reload applies config changes. Ordering matters for fail-closed behaviour:
// classification (nft) and kill switch tables go in before any tunnel moves.
func (d *Daemon) reload(selfCgroup string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	root := selfCgroup
	if d.plan != nil {
		root = d.plan.CgroupRoot
	}
	p, err := PrepareOn(d.ConfigPath, root, Env{Net: &d.netInfo, Links: d.links, Backend: d.Backend, Pass: d.ov.Passing(time.Now())})
	if err != nil {
		return err
	}
	if d.plan == nil {
		// First start: move ourselves into a leaf so our own traffic (endpoint
		// lookups) is never classified and the subtree root stays empty.
		if err := d.cg.Ensure(p.Plan.DaemonGroup.Path); err != nil {
			return fmt.Errorf("cgroup: %w", err)
		}
		if err := d.cg.Move(p.Plan.DaemonGroup.Path, os.Getpid()); err != nil {
			return fmt.Errorf("cgroup: move self: %w", err)
		}
	}
	for _, g := range p.Plan.Groups {
		if err := d.cg.Ensure(g.Path); err != nil {
			return fmt.Errorf("cgroup %s: %w", g.Name, err)
		}
	}
	var held map[string]engine.Group
	if d.fw != nil {
		held = d.fw.HeldFor(p.Plan.CgroupRoot)
	}
	if err := d.Backend.Apply(p.Ruleset, held); err != nil {
		return err
	}
	if d.proxy == nil {
		d.proxy = dnsproxy.New(d.Log, d.Backend.DomainSets())
	}
	ups := d.upstreams(p)
	if err := d.proxy.Update(p.Plan, ups); err != nil {
		return err
	}
	d.dnsUps = ups
	if d.filter != nil {
		var used []string
		if p.Plan.DNS {
			used = p.Config.UsedFilterLevels()
		}
		d.filter.Configure(p.Config.Filter(), used)
	}
	for _, w := range p.Warnings {
		d.Log.Warn(w)
	}
	d.cfg, d.plan, d.prep = p.Config, p.Plan, p
	wasPassing := d.passing
	d.passing = d.ov.Passing(time.Now())
	if wasPassing && !d.passing {
		// TCP keeps its route (sticky): flows opened direct during the pass
		// are classified again by their app, so nothing stays unprotected
		if dr := p.Plan.RouteByName("direct"); dr != nil {
			n, err := d.Backend.ForgetTCP(dr.Mark)
			d.Log.Info("pass ended: direct TCP connections re-classified", "count", n, "err", err)
		}
	}
	if d.fw == nil {
		d.fw = &firewall.Manager{Log: d.Log, CG: d.cg, Hold: d.Backend.Hold, Store: filepath.Join(filepath.Dir(d.ConfigPath), "apps.json")}
	}
	if err := d.fw.Configure(firewallSettings(p)); err != nil {
		d.Log.Warn("app firewall", "err", err)
	}
	if d.watcher == nil {
		d.watcher = d.Backend.Watcher(d.Log, d.fw.Unknown)
		d.fw.Placed = d.watcher.Place
	}
	d.watcher.SetRecheck(path.Join(p.Plan.CgroupRoot, "apps", "ask"))
	var targets []appwatch.Target
	for _, r := range p.Plan.AppRules() {
		targets = append(targets, appwatch.Target{Name: r.Name, Sels: r.Apps, Args: r.Args, Path: r.Groups[0].Path})
	}
	d.watcher.SetTargets(targets, p.Plan.CgroupRoot)
	// After a restart the processes are still in their groups but the new
	// watcher does not know them: adopt them, so sticky routes keep working.
	for _, g := range append(p.Plan.Groups, engine.Group{Path: path.Join(p.Plan.CgroupRoot, "apps", "free")}) {
		procs, _ := d.cg.Procs(g.Path)
		for _, pid := range procs {
			d.watcher.Place(pid, g.Path)
		}
	}
	return d.syncTunnels()
}

// syncTunnels brings tunnels in line with the prepared config. Tunnels that
// changed or vanished go down first; their tables keep the unreachable route,
// so their traffic is blocked meanwhile. Caller holds d.mu.
func (d *Daemon) syncTunnels() error {
	p := d.prep
	for name, t := range d.tunnels {
		if p.Config.Tunnels[name].Disabled {
			d.Log.Info("tunnel switched off", "tunnel", name)
			t.Down()
			delete(d.tunnels, name)
			delete(d.specHash, name)
			continue
		}
		if p.Hashes[name] != d.specHash[name] || !t.Alive() {
			if !t.Alive() {
				d.Log.Warn("tunnel interface vanished, restarting", "tunnel", name)
			}
			t.Down()
			delete(d.tunnels, name)
			delete(d.specHash, name)
		}
	}
	if err := d.syncRoutes(p.Plan, d.ifaceUp(p)); err != nil {
		return err
	}
	d.tunErrors = map[string]string{}
	for name, tc := range p.Config.Tunnels {
		if _, ok := d.tunnels[name]; ok || tc.Disabled {
			continue
		}
		// A second hop's encrypted packets take the first hop's route.
		mark := engine.MarkBypass
		if tc.Via != "" {
			mark = p.Plan.RouteByName(tc.Via).Mark
		}
		var t tunnel.Device
		var err error
		if tc.IsTailscale() {
			t, err = tunnel.StartTailscale(tunnel.TailscaleSpec{Name: name, Iface: tc.Interface, Conf: p.TS[name],
				RunDir: filepath.Dir(p.Config.Daemon.Socket), StateDir: filepath.Join("/var/lib/shunt", "ts-"+name)}, d.Log, d.signalTunnel)
		} else if tc.IsOpenVPN() {
			d.pushed.Delete(name)
			t, err = tunnel.StartOpenVPN(tunnel.OpenVPNSpec{Name: name, Iface: tc.Interface, Config: d.absConf(tc.Config),
				AuthFile: p.AuthFiles[name], Mark: mark, PIDDir: filepath.Dir(p.Config.Daemon.Socket)}, d.Log, d.signalTunnel)
		} else {
			t, err = tunnel.Up(tunnel.Spec{Name: name, Iface: tc.Interface, Driver: tc.Driver, Conf: hopConf(p, name), Mark: mark}, d.Log)
		}
		if err != nil {
			d.Log.Error("tunnel up failed, its traffic stays blocked", "tunnel", name, "err", err)
			d.tunErrors[name] = err.Error()
			continue
		}
		d.tunnels[name] = t
		d.specHash[name] = p.Hashes[name]
		d.Log.Info("tunnel up", "tunnel", name, "iface", tc.Interface, "driver", t.DriverName(), "via", tc.Via)
	}
	return d.syncRoutes(p.Plan, d.ifaceUp(p))
}

// firewallSettings derives the app firewall settings from a prepared config.
func firewallSettings(p *Prepared) firewall.Settings {
	groups := map[string]string{}
	for _, r := range p.Plan.Routes {
		if g, ok := p.Plan.Group(engine.ViaGroupName(r.String())); ok {
			groups[r.String()] = g.Path
		}
	}
	s := firewall.Settings{Mode: p.Config.FirewallMode(p.Network), Timeout: time.Duration(p.Config.FirewallTimeout()) * time.Second,
		Root: p.Plan.CgroupRoot, Groups: groups}
	if p.Config.Firewall != nil {
		s.AskTerminal = p.Config.Firewall.AskTerminal
	}
	return s
}

// checkNetwork follows network changes (Wi-Fi roaming, cable plugged in)
// and switches the default route when a [[network]] profile starts or stops
// matching.
func (d *Daemon) checkNetwork() {
	info, ls := netdetect.Current(), links.Current()
	d.mu.Lock()
	// another Wi-Fi/cable interface in use: the ruleset names it
	relink := ls.Names() != d.links.Names()
	if ls.Key() != d.links.Key() {
		d.setLinks(ls)
		if !relink && d.prep != nil { // same interfaces, new gateway
			if err := d.syncRoutes(d.plan, d.ifaceUp(d.prep)); err != nil {
				d.Log.Warn("routing sync after link change", "err", err)
			}
		}
	}
	moved := info.Key() != d.netInfo.Key()
	if relink {
		d.Log.Info("connections changed", "links", ls.Names())
		d.netRetry = true // reload below
	}
	if !moved && !d.netRetry {
		d.mu.Unlock()
		return
	}
	d.netInfo = info
	if moved {
		go d.probeCaptive()
		if d.prep != nil { // allow_lan routes follow the attached networks
			if err := d.syncRoutes(d.plan, d.ifaceUp(d.prep)); err != nil {
				d.Log.Warn("routing sync after network change", "err", err)
			}
		}
	}
	want := ""
	if n := d.cfg.MatchNetwork(info.SSID, info.GatewayMAC); n != nil {
		want = n.Name
	}
	have, root := d.prep.Network, d.plan.CgroupRoot
	retry := d.netRetry
	d.netRetry = false
	d.mu.Unlock()
	if want == have && !retry {
		return
	}
	d.Log.Info("network changed", "ssid", info.SSID, "gateway_mac", info.GatewayMAC, "profile", want, "previous", have)
	if err := d.reload(root); err != nil {
		// the old profile's default route stays in force: try again on
		// the next tick instead of waiting for the next network change
		d.Log.Error("reload for network change failed, retrying", "err", err)
		d.mu.Lock()
		d.netRetry = true
		d.mu.Unlock()
	}
}

// syncRoutes brings the routing tables in line with plan. Routes that could
// not be copied yet (a link coming up: its table blocks meanwhile) are
// logged and retried on the next network tick instead of failing a reload.
// Caller holds d.mu.
func (d *Daemon) syncRoutes(plan *engine.Plan, up map[string]bool) error {
	hard, soft := routing.Split(d.Backend.SyncRoutes(plan, up))
	msg := ""
	for _, e := range soft {
		msg += e.Error() + "; "
	}
	if msg != "" && msg != d.routeSoft {
		d.Log.Warn("routes not in place yet, retrying", "errors", msg)
	}
	d.routeSoft = msg
	return hard
}

// setLinks stores the connected links and their DNS servers. Caller holds
// d.mu (or runs before anything else).
func (d *Daemon) setLinks(ls links.State) {
	d.links = ls
	for _, k := range config.LinkKinds {
		d.linkDNS.Store(k, ls[k].DNS)
	}
}

// usedLinks lists the link kinds that rules, the default route or tunnels
// (via) use.
func usedLinks(c *config.Config, p *engine.Plan) []string {
	used := map[string]bool{}
	mark := func(s string) {
		if k, ok := strings.CutPrefix(s, "link:"); ok {
			used[k] = true
		}
	}
	mark(p.DefaultRoute.String())
	for _, r := range p.Rules {
		if !strings.HasPrefix(r.Name, "via:") && r.Route != nil { // not the implicit run-in-route rules
			mark(r.Route.String())
		}
	}
	for _, t := range c.Tunnels {
		mark(t.Via)
	}
	var out []string
	for _, k := range config.LinkKinds {
		if used[k] {
			out = append(out, k)
		}
	}
	return out
}

func linkLabel(kind string) string {
	switch kind {
	case "wifi":
		return "Wi-Fi"
	case "ethernet":
		return "cable (Ethernet)"
	}
	return "mobile (LTE/5G)"
}

// HopOverhead is what one WireGuard encapsulation adds (IPv6 outer header
// worst case): a hop inside another tunnel needs that much less MTU.
const HopOverhead = 80

// hopConf returns the WireGuard config to use for a tunnel; a second hop
// without its own MTU gets the outer tunnel's MTU minus HopOverhead.
func hopConf(p *Prepared, name string) *wgconf.Config {
	wc := p.Confs[name]
	tc := p.Config.Tunnels[name]
	if tc.Via == "" || wc.MTU != 0 || strings.HasPrefix(tc.Via, "link:") {
		return wc
	}
	outer := strings.TrimPrefix(tc.Via, "tunnel:")
	mtu := tunnel.DefaultMTU
	if p.Config.Tunnels[outer].IsTailscale() {
		mtu = 1280
	} else if p.Config.Tunnels[outer].IsOpenVPN() {
		mtu = 1500
	} else if oc := p.Confs[outer]; oc != nil && oc.MTU != 0 {
		mtu = oc.MTU
	} else if oc != nil && p.Config.Tunnels[outer].Via != "" {
		mtu = hopConf(p, outer).MTU // hop of a hop
	}
	c := *wc
	c.MTU = mtu - HopOverhead
	return &c
}

func quoteSSID(s string) string {
	if s == "" {
		return ""
	}
	return " (" + strconv.Quote(s) + ")"
}

// probeCaptive looks for a Wi-Fi login page (see package captive).
func (d *Daemon) probeCaptive() {
	d.mu.Lock()
	if d.probing || (d.cfg != nil && d.cfg.Daemon.CaptiveCheck != nil && !*d.cfg.Daemon.CaptiveCheck) {
		d.mu.Unlock()
		return
	}
	d.probing = true
	d.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	state, login := captive.Probe(ctx, captive.URL())
	cancel()
	d.mu.Lock()
	defer d.mu.Unlock()
	d.probing, d.captiveAt = false, time.Now()
	if state != d.captive {
		switch state {
		case captive.Portal:
			d.Log.Warn("Wi-Fi login page detected: tunnels cannot connect until you log in (shunt captive)", "page", login, "ssid", d.netInfo.SSID)
		case captive.Online:
			if d.captive == captive.Portal {
				d.Log.Info("Wi-Fi login done, network is open")
			}
		}
	}
	d.captive, d.captiveURL = state, login
}

// signalTunnel is called by OpenVPN tunnels from their own goroutines; it
// must never block (Down waits for those goroutines while holding d.mu).
func (d *Daemon) signalTunnel() {
	select {
	case d.tunEvents <- struct{}{}:
	default:
	}
}

// tunnelChanged picks up an OpenVPN (re)connect: its interface addresses
// decide which families get routes, and its pushed DNS servers.
func (d *Daemon) tunnelChanged() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for name, t := range d.tunnels {
		if o, ok := t.(tunnel.Pusher); ok {
			d.pushed.Store(name, o.DNS())
		}
	}
	if d.prep != nil {
		if err := d.syncRoutes(d.plan, d.ifaceUp(d.prep)); err != nil {
			d.Log.Error("routing sync failed", "err", err)
		}
	}
}

func (d *Daemon) ifaceUp(p *Prepared) map[string]bool {
	up := map[string]bool{}
	for name := range d.tunnels {
		if tc, ok := p.Config.Tunnels[name]; ok {
			up[tc.Interface] = true
		}
	}
	return up
}

func (d *Daemon) watchdog() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.watchdogLocked()
}

func (d *Daemon) watchdogLocked() {
	if len(d.tunErrors) > 0 || d.anyDead() {
		if err := d.syncTunnels(); err != nil {
			d.Log.Error("tunnel resync failed", "err", err)
		}
	}
	for name, t := range d.tunnels {
		changed, err := t.Reresolve(time.Now())
		if err != nil {
			d.Log.Warn("endpoint re-resolve failed", "tunnel", name, "err", err)
		}
		for _, c := range changed {
			// A changed endpoint is expected with DDNS, but could also be
			// DNS manipulation: always log it.
			d.Log.Warn("endpoint changed", "tunnel", name, "change", c)
		}
	}
}

func (d *Daemon) anyDead() bool {
	for _, t := range d.tunnels {
		if !t.Alive() {
			return true
		}
	}
	return false
}

// linkAbsent tells whether route is a link route (link:wifi, …) whose
// connection does not exist right now. Called with d.mu held.
func (d *Daemon) linkAbsent(route string) bool {
	if d.plan == nil || !strings.HasPrefix(route, "link:") {
		return false
	}
	for _, r := range d.plan.Routes {
		if r.Kind == config.RouteLink && r.String() == route {
			return r.Iface == ""
		}
	}
	return false
}

// shutdown removes tunnels but leaves nft rules and kill switch tables in
// place: traffic of tunnelled apps stays blocked until shuntd is back or
// `shuntd cleanup` is run explicitly.
func (d *Daemon) shutdown() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, t := range d.tunnels {
		t.Down()
	}
	d.tunnels = map[string]tunnel.Device{}
	if d.book != nil {
		_ = d.book.Close()
	}
	if d.plan != nil {
		_ = d.Backend.SyncRoutes(d.plan, nil) // shutting down: soft or not
	}
	if d.plan != nil {
		// tunnels' DNS keeps going to the closed proxy (fails closed), direct
		// DNS reaches the system resolver again
		if err := d.Backend.Stopped(d.plan); err != nil {
			d.Log.Warn("direct DNS stays blocked while shuntd is down", "err", err)
		}
	}
	if d.proxy != nil {
		d.proxy.Close()
	}
	_ = os.Remove(d.cfg.Daemon.Socket)
	d.Log.Info("shuntd stopped; kill switch stays active for tunnels, direct goes on")
}

func (d *Daemon) listen() (net.Listener, error) {
	sock := d.cfg.Daemon.Socket
	if err := os.MkdirAll(filepath.Dir(sock), 0o755); err != nil {
		return nil, err
	}
	_ = os.Remove(sock)
	ln, err := listenPrivate(sock)
	if err != nil {
		return nil, err
	}
	if g := d.cfg.Daemon.SocketGroup; g != "" {
		grp, err := user.LookupGroup(g)
		if err != nil {
			ln.Close()
			return nil, fmt.Errorf("socket_group: %w", err)
		}
		gid, _ := strconv.Atoi(grp.Gid)
		if err := os.Chown(sock, 0, gid); err != nil {
			ln.Close()
			return nil, err
		}
		if err := os.Chmod(sock, 0o660); err != nil {
			ln.Close()
			return nil, err
		}
	}
	return ln, nil
}

func (d *Daemon) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, d.status())
	})
	mux.HandleFunc("GET /v1/history", func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		book := d.book
		d.mu.Unlock()
		if book == nil {
			book, _ = stats.Open("")
		}
		writeJSON(w, http.StatusOK, book.History(r.URL.Query().Get("range"), time.Now()))
	})
	mux.HandleFunc("POST /v1/run", func(w http.ResponseWriter, r *http.Request) {
		p := peerOf(r.Context())
		if p == nil || !p.alive() {
			writeErr(w, http.StatusForbidden, errors.New("no peer credentials"))
			return
		}
		var req api.RunRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		d.mu.Lock()
		g, ok := d.plan.Group(req.Group)
		from, to := d.leaveRoute(int(p.pid)), d.groupRoute(g)
		// a Wi-Fi login page: the tunnels can't connect anyway, and the
		// login browser (shunt captive) has to go direct
		portal := d.captive == captive.Portal && to == "direct"
		d.mu.Unlock()
		if !ok {
			writeErr(w, http.StatusNotFound, fmt.Errorf("unknown group %q", req.Group))
			return
		}
		// A process that already runs in a route may only move to the same
		// route or to block; anything else is an escape and needs manage.
		if from != "" && from != to && to != "block" && !portal {
			if err := d.authorize(r.Context(), p); err != nil {
				writeErr(w, http.StatusForbidden, fmt.Errorf("leaving route %s: %w", from, err))
				return
			}
		}
		// PID reuse: only move the process that asked, verified by start time
		// before and after the move.
		if !p.alive() {
			writeErr(w, http.StatusForbidden, errors.New("caller is gone"))
			return
		}
		if err := d.cg.Move(g.Path, int(p.pid)); err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		if !p.alive() {
			d.Log.Warn("caller vanished during attach", "pid", p.pid)
			writeErr(w, http.StatusConflict, errors.New("caller is gone"))
			return
		}
		d.watcher.Place(int(p.pid), g.Path) // desktops/browsers move it into scopes: keep it here
		d.Log.Info("process attached", "pid", p.pid, "uid", p.uid, "group", g.Name)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /v1/adopt", func(w http.ResponseWriter, r *http.Request) {
		p := peerOf(r.Context())
		if p == nil || !p.alive() {
			writeErr(w, http.StatusForbidden, errors.New("no peer credentials"))
			return
		}
		var req api.AdoptRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		if len(req.PIDs) == 0 || len(req.PIDs) > 64 {
			writeErr(w, http.StatusBadRequest, errors.New("1 to 64 pids"))
			return
		}
		d.mu.Lock()
		g, ok := d.plan.Group(req.Group)
		d.mu.Unlock()
		if !ok {
			writeErr(w, http.StatusNotFound, fmt.Errorf("unknown group %q", req.Group))
			return
		}
		moved := 0
		for _, pid := range req.PIDs {
			if err := d.adoptable(p, pid); err != nil {
				d.Log.Debug("adopt refused", "pid", pid, "why", err)
				continue
			}
			if err := d.cg.Move(g.Path, pid); err != nil {
				continue // gone already
			}
			d.watcher.Place(pid, g.Path)
			moved++
			d.Log.Info("process adopted", "pid", pid, "uid", p.uid, "group", g.Name)
		}
		writeJSON(w, http.StatusOK, map[string]int{"moved": moved})
	})
	mux.HandleFunc("POST /v1/probe", func(w http.ResponseWriter, r *http.Request) {
		var req api.ProbeRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		d.mu.Lock()
		g, ok := d.plan.Group(engine.ViaGroupName(req.Route))
		d.mu.Unlock()
		if !ok {
			writeErr(w, http.StatusNotFound, fmt.Errorf("unknown route %q", req.Route))
			return
		}
		out, err := d.runProbe(r.Context(), g.Path)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(out)
	})
	mux.HandleFunc("POST /v1/reload", func(w http.ResponseWriter, r *http.Request) {
		if err := d.authorize(r.Context(), peerOf(r.Context())); err != nil {
			writeErr(w, http.StatusForbidden, err)
			return
		}
		d.mu.Lock()
		root := d.plan.CgroupRoot
		d.mu.Unlock()
		if err := d.reload(root); err != nil {
			writeErr(w, http.StatusUnprocessableEntity, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /v1/dnsfilter/refresh", func(w http.ResponseWriter, r *http.Request) {
		if err := d.authorize(r.Context(), peerOf(r.Context())); err != nil {
			writeErr(w, http.StatusForbidden, err)
			return
		}
		d.filter.Refresh()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /v1/config", func(w http.ResponseWriter, r *http.Request) {
		v, err := d.configView()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, v)
	})
	rawOf := func(req api.ConfigSave) ([]byte, error) {
		if req.Config != nil {
			// Only these daemon settings are locked to the file; the rest of
			// [daemon] (default_route) is editable.
			d.mu.Lock()
			cur := d.cfg.Daemon
			d.mu.Unlock()
			req.Config.Daemon.Socket = cur.Socket
			req.Config.Daemon.SocketGroup = cur.SocketGroup
			req.Config.Daemon.CgroupRoot = cur.CgroupRoot
			req.Config.Daemon.APIAuth = cur.APIAuth
			return req.Config.Encode()
		}
		if req.Raw == "" {
			return nil, errors.New("empty config")
		}
		return []byte(req.Raw), nil
	}
	mux.HandleFunc("POST /v1/config/check", func(w http.ResponseWriter, r *http.Request) {
		var req api.ConfigSave
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		raw, err := rawOf(req)
		var p *Prepared
		if err == nil {
			p, err = d.checkCandidate(raw)
		}
		if err != nil {
			writeJSON(w, http.StatusOK, api.CheckResult{Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, api.CheckResult{OK: true, Warnings: p.Warnings})
	})
	mux.HandleFunc("PUT /v1/config", func(w http.ResponseWriter, r *http.Request) {
		if err := d.authorize(r.Context(), peerOf(r.Context())); err != nil {
			writeErr(w, http.StatusForbidden, err)
			return
		}
		var req api.ConfigSave
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		raw, err := rawOf(req)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		p, err := d.saveConfig(raw, req.Version)
		if errors.Is(err, errConflict) {
			writeErr(w, http.StatusConflict, err)
			return
		}
		if err != nil {
			writeErr(w, http.StatusUnprocessableEntity, err)
			return
		}
		writeJSON(w, http.StatusOK, api.CheckResult{OK: true, Warnings: p.Warnings})
	})
	mux.HandleFunc("POST /v1/tunnels", func(w http.ResponseWriter, r *http.Request) {
		if err := d.authorize(r.Context(), peerOf(r.Context())); err != nil {
			writeErr(w, http.StatusForbidden, err)
			return
		}
		var req api.TunnelImport
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<18)).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		p, err := d.importTunnel(req)
		if err != nil {
			writeErr(w, http.StatusUnprocessableEntity, err)
			return
		}
		writeJSON(w, http.StatusOK, api.CheckResult{OK: true, Warnings: p.Warnings})
	})
	mux.HandleFunc("DELETE /v1/tunnels/{name}", func(w http.ResponseWriter, r *http.Request) {
		if err := d.authorize(r.Context(), peerOf(r.Context())); err != nil {
			writeErr(w, http.StatusForbidden, err)
			return
		}
		if err := d.deleteTunnel(r.PathValue("name")); err != nil {
			writeErr(w, http.StatusUnprocessableEntity, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /v1/tunnels/{name}/rename", func(w http.ResponseWriter, r *http.Request) {
		if err := d.authorize(r.Context(), peerOf(r.Context())); err != nil {
			writeErr(w, http.StatusForbidden, err)
			return
		}
		var req api.TunnelRename
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		if err := d.renameTunnel(r.PathValue("name"), req.To); err != nil {
			writeErr(w, http.StatusUnprocessableEntity, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /v1/pending", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, d.fw.List())
	})
	mux.HandleFunc("POST /v1/pending/{id}", func(w http.ResponseWriter, r *http.Request) {
		var req api.FirewallDecision
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		// A program that is itself held or routed must not let itself out:
		// deciding is for the desktop user (or root/polkit).
		if p := peerOf(r.Context()); p == nil || d.inShuntGroup(int(p.pid)) {
			if err := d.authorize(r.Context(), p); err != nil {
				writeErr(w, http.StatusForbidden, fmt.Errorf("deciding from inside a route: %w", err))
				return
			}
		}
		if err := d.fw.Decide(r.PathValue("id"), req.Route, req.Remember); err != nil {
			code := http.StatusUnprocessableEntity
			if errors.Is(err, firewall.ErrUnknown) {
				code = http.StatusNotFound
			}
			writeErr(w, code, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /v1/firewall/apps", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, d.fw.Remembered())
	})
	mux.HandleFunc("DELETE /v1/firewall/apps", func(w http.ResponseWriter, r *http.Request) {
		// same as deciding: a blocked program must not forget its own block
		if p := peerOf(r.Context()); p == nil || d.inShuntGroup(int(p.pid)) {
			if err := d.authorize(r.Context(), p); err != nil {
				writeErr(w, http.StatusForbidden, fmt.Errorf("forgetting from inside a route: %w", err))
				return
			}
		}
		if err := d.fw.Forget(r.URL.Query().Get("key")); err != nil {
			writeErr(w, http.StatusNotFound, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /v1/procs", func(w http.ResponseWriter, r *http.Request) {
		name := strings.ToLower(r.URL.Query().Get("name"))
		if name == "" {
			writeErr(w, http.StatusBadRequest, errors.New("name missing"))
			return
		}
		writeJSON(w, http.StatusOK, d.procs(name))
	})
	mux.HandleFunc("POST /v1/restart", func(w http.ResponseWriter, r *http.Request) {
		if err := d.authorize(r.Context(), peerOf(r.Context())); err != nil {
			writeErr(w, http.StatusForbidden, err)
			return
		}
		d.Log.Warn("restart requested via API", "uid", peerOf(r.Context()).uid)
		select {
		case d.restart <- struct{}{}:
		default:
		}
		w.WriteHeader(http.StatusAccepted)
	})
	mux.HandleFunc("POST /v1/pass", func(w http.ResponseWriter, r *http.Request) {
		var req api.PassRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		// letting everything through loosens protection: password
		if req.Minutes > 0 {
			if err := d.authorize(r.Context(), peerOf(r.Context())); err != nil {
				writeErr(w, http.StatusForbidden, err)
				return
			}
		}
		until := d.ov.Pass(time.Duration(req.Minutes)*time.Minute, time.Now())
		if err := d.reload(d.selfCgroup()); err != nil {
			d.ov.Pass(0, time.Now())
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		d.Log.Warn("pass", "minutes", req.Minutes, "until", until)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /v1/panic", func(w http.ResponseWriter, r *http.Request) {
		var req api.PanicRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		// panic ON never waits for a password; lifting it does
		if !req.On {
			if err := d.authorize(r.Context(), peerOf(r.Context())); err != nil {
				writeErr(w, http.StatusForbidden, err)
				return
			}
		}
		if err := d.Backend.Panic(req.On); err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		d.mu.Lock()
		d.panic = req.On
		d.mu.Unlock()
		d.Log.Warn("panic mode", "on", req.On)
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

// probeSlots limits concurrent leak test probes (one per route is normal).
var probeSlots = make(chan struct{}, 16)

// runProbe runs `shuntd probe` (fixed targets, nothing the caller chooses)
// inside the cgroup at path, so its traffic takes exactly that route. The
// probe waits for a line on stdin: it is moved before it sends anything.
func (d *Daemon) runProbe(ctx context.Context, path string) ([]byte, error) {
	select {
	case probeSlots <- struct{}{}:
		defer func() { <-probeSlots }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, selfExe(), "probe")
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	if err := d.cg.Move(path, cmd.Process.Pid); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, err
	}
	_, _ = in.Write([]byte("go\n"))
	in.Close()
	if err := cmd.Wait(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func (d *Daemon) status() api.Status {
	d.mu.Lock()
	defer d.mu.Unlock()
	ovs := d.ov.Status(time.Now())
	st := api.Status{DefaultRoute: d.plan.DefaultRoute.String(), Panic: d.panic, PassLeft: ovs.PassLeft, DNS: map[string][]string{},
		Network: d.prep.Network, NetInfo: d.netInfo, Captive: d.captive, CaptiveURL: d.captiveURL,
		Firewall: d.cfg.FirewallMode(d.prep.Network), Version: d.Version}
	if d.fw != nil {
		st.Pending = len(d.fw.List())
	}
	st.Warnings = append(st.Warnings, d.prep.Warnings...)
	if d.book != nil {
		st.Traffic = d.book.Summaries(time.Now())
	}
	for route, ups := range d.dnsUps {
		for _, u := range ups {
			st.DNS[route] = append(st.DNS[route], u.String())
			if su, ok := u.(*dnsproxy.SystemUpstream); ok && len(su.Servers()) == 0 {
				st.Warnings = append(st.Warnings, "no system DNS resolver found for the direct route (yet): set dns.direct if this persists")
			}
		}
	}
	if d.captive == captive.Portal {
		st.Warnings = append(st.Warnings, fmt.Sprintf("Wi-Fi login page in the way%s: tunnels can't connect until you log in – shunt captive (or the tray: Wi-Fi login page)", quoteSSID(d.netInfo.SSID)))
	}
	if d.proxy != nil {
		if f := d.proxy.Health(); len(f) > 0 {
			st.DNSFailing = f
			routes := make([]string, 0, len(f))
			for r := range f {
				// a switched-off tunnel is blocked on purpose, DNS included
				if t, ok := d.cfg.Tunnels[strings.TrimPrefix(r, "tunnel:")]; ok && strings.HasPrefix(r, "tunnel:") && t.Disabled {
					delete(f, r)
					continue
				}
				// no Wi-Fi / mobile connection (or no such hardware): its
				// route is blocked on purpose, there is no DNS to expect
				if d.linkAbsent(r) {
					delete(f, r)
					continue
				}
				routes = append(routes, r)
			}
			sort.Strings(routes)
			for _, r := range routes {
				hint := ""
				if strings.HasPrefix(r, "tunnel:") {
					hint = " – is that DNS server reachable through the tunnel? A server in your home network usually is not"
				}
				st.Warnings = append(st.Warnings, fmt.Sprintf("DNS for %s fails (%s)%s", r, f[r], hint))
			}
		}
	}
	names := make([]string, 0, len(d.cfg.Tunnels))
	for n := range d.cfg.Tunnels {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		ts := api.TunnelStatus{Name: n, Iface: d.cfg.Tunnels[n].Interface, Error: d.tunErrors[n], Via: d.cfg.Tunnels[n].Via, Disabled: d.cfg.Tunnels[n].Disabled}
		if t, ok := d.tunnels[n]; ok {
			ts.Up, ts.Driver = true, t.DriverName()
			ts.Peers, _ = t.Status()
			ts.Health = d.healthReport(n)
			if e := t.Err(); e != "" && ts.Error == "" {
				ts.Error = e
			}
			if o, ok := t.(tunnel.Pusher); ok && o.Connected() && d.cfg.Tunnels[n].DNS == "" && len(o.DNS()) == 0 {
				st.Warnings = append(st.Warnings, fmt.Sprintf("tunnel %q: the OpenVPN server pushed no DNS server; set dns = \"<upstream>\" for it", n))
			}
		}
		st.Tunnels = append(st.Tunnels, ts)
	}
	for _, r := range d.plan.Routes {
		st.Routes = append(st.Routes, r.String())
	}
	for _, g := range d.plan.Groups {
		procs, _ := d.cg.Procs(g.Path)
		gs := api.GroupStatus{Name: g.Name, Procs: len(procs), Apps: d.procNames(procs)}
	rules:
		for _, r := range d.plan.Rules {
			for _, rg := range r.Groups {
				if rg.Path == g.Path {
					gs.Route = ruleRoute(d.plan, r)
					break rules
				}
			}
		}
		st.Groups = append(st.Groups, gs)
	}
	if d.plan.DNS && d.filter != nil {
		fs := &api.DNSFilterStatus{Default: d.cfg.Filter().Default, Routes: map[string]string{}, Rules: map[string]string{},
			Lists: d.filter.Status(), Stats: d.proxy.FilterStats()}
		for _, r := range d.plan.Routes {
			if r.Kind != config.RouteBlock {
				fs.Routes[r.String()] = r.Filter
			}
		}
		for _, r := range d.plan.Rules {
			if r.Filter != "" {
				fs.Rules[r.Name] = r.Filter
			}
		}
		st.DNSFilter = fs
	}
	for _, r := range d.plan.Rules {
		line := fmt.Sprintf("%s -> %s", r.Name, ruleRoute(d.plan, r))
		if r.Filter != "" {
			line += ", dns filter " + r.Filter
		}
		st.Rules = append(st.Rules, line)
	}
	return st
}

// procs lists processes whose name contains name, with their route.
func (d *Daemon) procs(name string) []api.ProcRoute {
	pids := d.Backend.Pids()
	d.mu.Lock()
	defer d.mu.Unlock()
	out := []api.ProcRoute{}
	for _, pid := range pids {
		comm, ok := d.Backend.Comm(pid)
		if !ok || !strings.Contains(strings.ToLower(comm), name) {
			continue
		}
		pr := api.ProcRoute{PID: pid, Name: comm}
		if g, ok := d.groupOf(pid); ok {
			pr.Group, pr.Route = g.Name, d.groupRoute(g)
		} else {
			pr.Route = d.plan.DefaultRoute.String() + " (default)"
		}
		out = append(out, pr)
		if len(out) >= 200 {
			break
		}
	}
	return out
}

// inShuntGroup reports whether pid runs inside Shunt's cgroup tree (a
// route group or a waiting group).
func (d *Daemon) inShuntGroup(pid int) bool {
	cg, ok := d.Backend.CgroupOf(pid)
	if !ok {
		return true // gone or unreadable: treat as untrusted
	}
	d.mu.Lock()
	root := d.plan.CgroupRoot
	d.mu.Unlock()
	return under(cg, path.Join(root, "apps"))
}

// under reports whether cgroup cg is dir or below it.
func under(cg, dir string) bool { return cg == dir || strings.HasPrefix(cg, dir+"/") }

// leaveRoute is the route pid would leave by moving: its group's route,
// "block" while the app firewall holds it (or it is gone), the default
// route otherwise – "" when that is direct, which anyone may leave.
// Caller holds d.mu.
func (d *Daemon) leaveRoute(pid int) string {
	cg, ok := d.Backend.CgroupOf(pid)
	if !ok {
		return "block"
	}
	return fromRoute(cg, d.plan, d.groupRoute)
}

func fromRoute(cg string, p *engine.Plan, groupRoute func(engine.Group) string) string {
	for _, g := range p.Groups {
		if under(cg, g.Path) {
			return groupRoute(g)
		}
	}
	if under(cg, path.Join(p.CgroupRoot, "apps", "ask")) {
		return "block" // held by the app firewall: leaving is an escape
	}
	if p.DefaultRoute.Kind == config.RouteDirect {
		return ""
	}
	return p.DefaultRoute.String()
}

// groupOf returns the Shunt group pid is in. Caller holds d.mu.
func (d *Daemon) groupOf(pid int) (engine.Group, bool) {
	cg, ok := d.Backend.CgroupOf(pid)
	if !ok {
		return engine.Group{}, false
	}
	for _, g := range d.plan.Groups {
		if cg == g.Path || strings.HasPrefix(cg, g.Path+"/") {
			return g, true
		}
	}
	return engine.Group{}, false
}

// procNames returns the distinct program names of pids.
func (d *Daemon) procNames(pids []int) []string {
	seen := map[string]bool{}
	var out []string
	for _, pid := range pids {
		n, ok := d.Backend.Comm(pid)
		if ok && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// statsPath: systemd's StateDirectory (/var/lib/shunt), or next to the
// config for units installed before traffic statistics existed.
func (d *Daemon) statsPath() string {
	if dir, _, _ := strings.Cut(os.Getenv("STATE_DIRECTORY"), ":"); dir != "" {
		return filepath.Join(dir, "stats.json")
	}
	return filepath.Join(filepath.Dir(d.ConfigPath), "stats.json")
}

// filterDir is where blocklists are cached: systemd's CacheDirectory
// (/var/cache/shunt), or next to the config for units installed before the
// DNS filter existed.
func (d *Daemon) filterDir() string {
	if c, _, _ := strings.Cut(os.Getenv("CACHE_DIRECTORY"), ":"); c != "" {
		return filepath.Join(c, "blocklists")
	}
	return filepath.Join(filepath.Dir(d.ConfigPath), "blocklists")
}

// downloadClient: blocklist downloads take the default route (and its DNS).
func (d *Daemon) downloadClient() *http.Client {
	d.mu.Lock()
	r := d.plan.DefaultRoute
	d.mu.Unlock()
	return dnsproxy.RouteHTTPClient(r.Mark, r.DNSPort)
}

// ruleRoute names the route of rule r; a rule that only sets a DNS filter
// leaves its programs on the default route.
func ruleRoute(p *engine.Plan, r engine.Rule) string {
	if r.Route == nil {
		return p.DefaultRoute.String() + " (default)"
	}
	return r.Route.String()
}

// groupRoute is the route of the first rule using g. Caller holds d.mu.
func (d *Daemon) groupRoute(g engine.Group) string {
	for _, r := range d.plan.Rules {
		for _, rg := range r.Groups {
			if rg.Path == g.Path {
				return ruleRoute(d.plan, r)
			}
		}
	}
	return ""
}

func notifyHUP(c chan os.Signal) { signal.Notify(c, syscall.SIGHUP) }

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, api.Error{Error: err.Error()})
}

// Cleanup removes every trace of Shunt from the system: rules, routes and
// tables. This disables all kill switches.
func Cleanup() error {
	b := DefaultBackend()
	if b == nil {
		return errors.New("no backend for this platform")
	}
	return b.Cleanup()
}

// adoptable: pid belongs to the caller's user, lives in that user's slice and
// runs in no route yet (so adopting never lets anything out of a route).
func (d *Daemon) adoptable(p *peer, pid int) error {
	if pid <= 1 {
		return errors.New("bad pid")
	}
	st, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return err
	}
	uid := -1
	for _, l := range strings.Split(string(st), "\n") {
		if f := strings.Fields(l); len(f) >= 2 && f[0] == "Uid:" {
			uid, _ = strconv.Atoi(f[1])
		}
	}
	if uid < 0 || uint32(uid) != p.uid {
		return errors.New("not the caller's process")
	}
	cg, ok := d.Backend.CgroupOf(pid)
	if !ok {
		return errors.New("no cgroup")
	}
	if !strings.HasPrefix(cg, "/user.slice/user-"+strconv.Itoa(uid)+".slice/") {
		return fmt.Errorf("%s is not in the user's slice", cg)
	}
	d.mu.Lock()
	from := fromRoute(cg, d.plan, d.groupRoute)
	d.mu.Unlock()
	if from != "" {
		return fmt.Errorf("already in route %s", from)
	}
	return nil
}
