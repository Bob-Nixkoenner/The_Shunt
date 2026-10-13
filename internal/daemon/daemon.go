// Package daemon wires config, engine and the Linux backend together and
// serves the API.
package daemon

import (
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
	"os/signal"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Bob-Nixkoenner/the_shunt/internal/api"
	"github.com/Bob-Nixkoenner/the_shunt/internal/appwatch"
	"github.com/Bob-Nixkoenner/the_shunt/internal/cgroup"
	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/Bob-Nixkoenner/the_shunt/internal/dnsproxy"
	"github.com/Bob-Nixkoenner/the_shunt/internal/engine"
	"github.com/Bob-Nixkoenner/the_shunt/internal/netdetect"
	"github.com/Bob-Nixkoenner/the_shunt/internal/nft"
	"github.com/Bob-Nixkoenner/the_shunt/internal/ovpnconf"
	"github.com/Bob-Nixkoenner/the_shunt/internal/routing"
	"github.com/Bob-Nixkoenner/the_shunt/internal/tunnel"
	"github.com/Bob-Nixkoenner/the_shunt/internal/wgconf"
)

// Daemon is the running shuntd.
type Daemon struct {
	ConfigPath string
	Log        *slog.Logger

	mu        sync.Mutex
	cfg       *config.Config
	plan      *engine.Plan
	prep      *Prepared
	cg        cgroup.Manager
	tunnels   map[string]tunnel.Device
	specHash  map[string]string
	tunErrors map[string]string
	panic     bool
	proxy     *dnsproxy.Proxy
	watcher   *appwatch.Watcher
	saveMu    sync.Mutex // serializes config writes
	dnsUps    dnsproxy.RouteUpstreams
	// pushed holds the DNS servers OpenVPN servers pushed ([]netip.Addr per
	// tunnel name); read by the DNS proxy without d.mu.
	pushed sync.Map
	// tunEvents: an OpenVPN tunnel connected or disconnected.
	tunEvents chan struct{}
	netInfo   netdetect.Info
	restart   chan struct{}
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
func Prepare(path, cgroupRoot string) (*Prepared, error) { return PrepareOn(path, cgroupRoot, nil) }

// PrepareOn is Prepare for the network net is on: a matching [[network]]
// replaces the default route.
func PrepareOn(path, cgroupRoot string, net *netdetect.Info) (*Prepared, error) {
	c, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	if c.Daemon.CgroupRoot != "" {
		cgroupRoot = c.Daemon.CgroupRoot
	}
	p := &Prepared{Config: c, Confs: map[string]*wgconf.Config{}, OVPN: map[string]*ovpnconf.Config{}, AuthFiles: map[string]string{}, Hashes: map[string]string{}}
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
			eff, p.Network = &cc, n.Name
		}
	}
	p.Plan, err = engine.Compile(eff, cgroupRoot, infos)
	if err != nil {
		return nil, err
	}
	p.Ruleset, err = nft.Render(p.Plan)
	if err != nil {
		return nil, err
	}
	if p.Plan.DNS {
		p.prepareDNS()
	} else {
		p.Warnings = append(p.Warnings, "DNS routing is disabled: DNS queries leak past the tunnels")
	}
	return p, nil
}

func (p *Prepared) prepareDNS() {
	c := p.Config
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
		for _, d := range p.Confs[name].DNS {
			if a, err := netip.ParseAddr(d); err == nil {
				p.DNSUpstreams[route] = append(p.DNSUpstreams[route], config.UpstreamSpec{Proto: "udp", Addr: netip.AddrPortFrom(a, 53)})
			}
		}
		if len(p.DNSUpstreams[route]) == 0 {
			p.Warnings = append(p.Warnings, fmt.Sprintf("tunnel %q has no DNS server (DNS= in its config or dns = \"<upstream>\"): its apps cannot resolve names", name))
		}
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
	mount, err := cgroup.Mount()
	if err != nil {
		return err
	}
	self, err := cgroup.Self()
	if err != nil {
		return err
	}
	d.cg = cgroup.Manager{Mount: mount}
	d.tunnels = map[string]tunnel.Device{}
	d.tunEvents = make(chan struct{}, 1)
	d.restart = make(chan struct{}, 1)
	d.specHash = map[string]string{}
	d.tunErrors = map[string]string{}
	d.netInfo = netdetect.Current()

	if err := d.reload(self); err != nil {
		return err
	}
	// The plan is in place: lift the boot lockdown if it was set.
	if err := nft.Apply(nft.DeleteScript(nft.LockdownTable)); err != nil {
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
		case <-d.tunEvents:
			d.tunnelChanged()
		case <-netTick.C:
			d.checkNetwork()
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
	p, err := PrepareOn(d.ConfigPath, root, &d.netInfo)
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
	if err := nft.Apply(p.Ruleset); err != nil {
		return err
	}
	if d.proxy == nil {
		d.proxy = dnsproxy.New(d.Log, dnsproxy.NftSets{Table: nft.Table})
	}
	ups := d.upstreams(p)
	if err := d.proxy.Update(p.Plan, ups); err != nil {
		return err
	}
	d.dnsUps = ups
	for _, w := range p.Warnings {
		d.Log.Warn(w)
	}
	d.cfg, d.plan, d.prep = p.Config, p.Plan, p
	if d.watcher == nil {
		d.watcher = &appwatch.Watcher{Log: d.Log, Mover: d.cg}
	}
	var targets []appwatch.Target
	for _, r := range p.Plan.AppRules() {
		targets = append(targets, appwatch.Target{Name: r.Name, Sels: r.Apps, Args: r.Args, Path: r.Groups[0].Path})
	}
	d.watcher.SetTargets(targets, p.Plan.CgroupRoot)
	return d.syncTunnels()
}

// syncTunnels brings tunnels in line with the prepared config. Tunnels that
// changed or vanished go down first; their tables keep the unreachable route,
// so their traffic is blocked meanwhile. Caller holds d.mu.
func (d *Daemon) syncTunnels() error {
	p := d.prep
	for name, t := range d.tunnels {
		if p.Hashes[name] != d.specHash[name] || !t.Alive() {
			if !t.Alive() {
				d.Log.Warn("tunnel interface vanished, restarting", "tunnel", name)
			}
			t.Down()
			delete(d.tunnels, name)
			delete(d.specHash, name)
		}
	}
	if err := routing.Sync(p.Plan, d.ifaceUp(p)); err != nil {
		return err
	}
	d.tunErrors = map[string]string{}
	for name, tc := range p.Config.Tunnels {
		if _, ok := d.tunnels[name]; ok {
			continue
		}
		// A second hop's encrypted packets take the first hop's route.
		mark := engine.MarkBypass
		if tc.Via != "" {
			mark = p.Plan.RouteByName(tc.Via).Mark
		}
		var t tunnel.Device
		var err error
		if tc.IsOpenVPN() {
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
	return routing.Sync(p.Plan, d.ifaceUp(p))
}

// checkNetwork follows network changes (Wi-Fi roaming, cable plugged in)
// and switches the default route when a [[network]] profile starts or stops
// matching.
func (d *Daemon) checkNetwork() {
	info := netdetect.Current()
	d.mu.Lock()
	if info.Key() == d.netInfo.Key() {
		d.mu.Unlock()
		return
	}
	d.netInfo = info
	want := ""
	if n := d.cfg.MatchNetwork(info.SSID, info.GatewayMAC); n != nil {
		want = n.Name
	}
	have, root := d.prep.Network, d.plan.CgroupRoot
	d.mu.Unlock()
	if want == have {
		return
	}
	d.Log.Info("network changed", "ssid", info.SSID, "gateway_mac", info.GatewayMAC, "profile", want, "previous", have)
	if err := d.reload(root); err != nil {
		d.Log.Error("reload for network change failed", "err", err)
	}
}

// HopOverhead is what one WireGuard encapsulation adds (IPv6 outer header
// worst case): a hop inside another tunnel needs that much less MTU.
const HopOverhead = 80

// hopConf returns the WireGuard config to use for a tunnel; a second hop
// without its own MTU gets the outer tunnel's MTU minus HopOverhead.
func hopConf(p *Prepared, name string) *wgconf.Config {
	wc := p.Confs[name]
	tc := p.Config.Tunnels[name]
	if tc.Via == "" || wc.MTU != 0 {
		return wc
	}
	outer := strings.TrimPrefix(tc.Via, "tunnel:")
	mtu := tunnel.DefaultMTU
	if p.Config.Tunnels[outer].IsOpenVPN() {
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
		if o, ok := t.(*tunnel.OpenVPN); ok {
			d.pushed.Store(name, o.DNS())
		}
	}
	if d.prep != nil {
		if err := routing.Sync(d.plan, d.ifaceUp(d.prep)); err != nil {
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
	if d.plan != nil {
		_ = routing.Sync(d.plan, nil)
	}
	if d.proxy != nil {
		d.proxy.Close() // redirect rules stay: DNS fails closed while we're down
	}
	_ = os.Remove(d.cfg.Daemon.Socket)
	d.Log.Info("shuntd stopped; kill switch stays active")
}

func (d *Daemon) listen() (net.Listener, error) {
	sock := d.cfg.Daemon.Socket
	if err := os.MkdirAll(filepath.Dir(sock), 0o755); err != nil {
		return nil, err
	}
	_ = os.Remove(sock)
	old := unix.Umask(0o177)
	ln, err := net.Listen("unix", sock)
	unix.Umask(old)
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
		from, to := d.currentRoute(int(p.pid)), d.groupRoute(g)
		d.mu.Unlock()
		if !ok {
			writeErr(w, http.StatusNotFound, fmt.Errorf("unknown group %q", req.Group))
			return
		}
		// A process that already runs in a route may only move to the same
		// route or to block; anything else is an escape and needs manage.
		if from != "" && from != to && to != "block" {
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
		d.Log.Info("process attached", "pid", p.pid, "uid", p.uid, "group", g.Name)
		w.WriteHeader(http.StatusNoContent)
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
		script := nft.DeleteScript(nft.PanicTable)
		if req.On {
			script = nft.RenderPanic()
		}
		if err := nft.Apply(script); err != nil {
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

func (d *Daemon) status() api.Status {
	d.mu.Lock()
	defer d.mu.Unlock()
	st := api.Status{DefaultRoute: d.plan.DefaultRoute.String(), Panic: d.panic, DNS: map[string][]string{},
		Network: d.prep.Network, NetInfo: d.netInfo}
	st.Warnings = append(st.Warnings, d.prep.Warnings...)
	for route, ups := range d.dnsUps {
		for _, u := range ups {
			st.DNS[route] = append(st.DNS[route], u.String())
			if su, ok := u.(*dnsproxy.SystemUpstream); ok && len(su.Servers()) == 0 {
				st.Warnings = append(st.Warnings, "no system DNS resolver found for the direct route (yet): set dns.direct if this persists")
			}
		}
	}
	if d.proxy != nil {
		if f := d.proxy.Health(); len(f) > 0 {
			st.DNSFailing = f
			routes := make([]string, 0, len(f))
			for r := range f {
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
		ts := api.TunnelStatus{Name: n, Iface: d.cfg.Tunnels[n].Interface, Error: d.tunErrors[n], Via: d.cfg.Tunnels[n].Via}
		if t, ok := d.tunnels[n]; ok {
			ts.Up, ts.Driver = true, t.DriverName()
			ts.Peers, _ = t.Status()
			if e := t.Err(); e != "" && ts.Error == "" {
				ts.Error = e
			}
			if o, ok := t.(*tunnel.OpenVPN); ok && o.Connected() && d.cfg.Tunnels[n].DNS == "" && len(o.DNS()) == 0 {
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
		gs := api.GroupStatus{Name: g.Name, Procs: len(procs), Apps: procNames(procs)}
	rules:
		for _, r := range d.plan.Rules {
			for _, rg := range r.Groups {
				if rg.Path == g.Path {
					gs.Route = r.Route.String()
					break rules
				}
			}
		}
		st.Groups = append(st.Groups, gs)
	}
	for _, r := range d.plan.Rules {
		st.Rules = append(st.Rules, fmt.Sprintf("%s -> %s", r.Name, r.Route))
	}
	return st
}

// procs lists processes whose name contains name, with their route.
func (d *Daemon) procs(name string) []api.ProcRoute {
	ents, _ := os.ReadDir("/proc")
	d.mu.Lock()
	defer d.mu.Unlock()
	out := []api.ProcRoute{}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile("/proc/" + e.Name() + "/comm")
		comm := strings.TrimSpace(string(b))
		if err != nil || !strings.Contains(strings.ToLower(comm), name) {
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

// groupOf returns the Shunt group pid is in. Caller holds d.mu.
func (d *Daemon) groupOf(pid int) (engine.Group, bool) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cgroup")
	if err != nil {
		return engine.Group{}, false
	}
	var cg string
	for _, l := range strings.Split(string(b), "\n") {
		if c, ok := strings.CutPrefix(l, "0::"); ok {
			cg = strings.Trim(c, "/")
		}
	}
	for _, g := range d.plan.Groups {
		if cg == g.Path || strings.HasPrefix(cg, g.Path+"/") {
			return g, true
		}
	}
	return engine.Group{}, false
}

// procNames returns the distinct program names of pids.
func procNames(pids []int) []string {
	seen := map[string]bool{}
	var out []string
	for _, pid := range pids {
		b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm")
		if err != nil {
			continue
		}
		n := strings.TrimSpace(string(b))
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// currentRoute returns the route of the Shunt group pid is in, or "".
// Caller holds d.mu.
func (d *Daemon) currentRoute(pid int) string {
	if g, ok := d.groupOf(pid); ok {
		return d.groupRoute(g)
	}
	return ""
}

// groupRoute is the route of the first rule using g. Caller holds d.mu.
func (d *Daemon) groupRoute(g engine.Group) string {
	for _, r := range d.plan.Rules {
		for _, rg := range r.Groups {
			if rg.Path == g.Path {
				return r.Route.String()
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

// Cleanup removes every trace of Shunt from the kernel: nft tables, ip rules
// and routing tables. This disables all kill switches.
func Cleanup() error {
	var errs []error
	for _, t := range []string{nft.Table, nft.PanicTable, nft.LockdownTable} {
		errs = append(errs, nft.Apply(nft.DeleteScript(t)))
	}
	errs = append(errs, routing.Cleanup())
	return errors.Join(errs...)
}
