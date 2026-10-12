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
	"github.com/Bob-Nixkoenner/the_shunt/internal/cgroup"
	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/Bob-Nixkoenner/the_shunt/internal/dnsproxy"
	"github.com/Bob-Nixkoenner/the_shunt/internal/engine"
	"github.com/Bob-Nixkoenner/the_shunt/internal/nft"
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
	tunnels   map[string]*tunnel.Tunnel
	specHash  map[string]string
	tunErrors map[string]string
	panic     bool
	proxy     *dnsproxy.Proxy
}

// Prepared is the result of loading config and tunnel files.
type Prepared struct {
	Config  *config.Config
	Plan    *engine.Plan
	Confs   map[string]*wgconf.Config
	Hashes  map[string]string
	Ruleset string
	// DNS upstreams per route name, and problems worth telling the user.
	DNSUpstreams map[string][]config.UpstreamSpec
	Warnings     []string
}

// Prepare loads everything and compiles the plan without touching the system.
func Prepare(path, cgroupRoot string) (*Prepared, error) {
	c, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	if c.Daemon.CgroupRoot != "" {
		cgroupRoot = c.Daemon.CgroupRoot
	}
	p := &Prepared{Config: c, Confs: map[string]*wgconf.Config{}, Hashes: map[string]string{}}
	infos := map[string]engine.TunnelInfo{}
	for name, t := range c.Tunnels {
		cp := t.Config
		if !filepath.IsAbs(cp) {
			cp = filepath.Join(filepath.Dir(path), cp)
		}
		if err := checkSecretFile(cp); err != nil {
			return nil, fmt.Errorf("tunnel %q: %w", name, err)
		}
		raw, err := os.ReadFile(cp)
		if err != nil {
			return nil, fmt.Errorf("tunnel %q: %w", name, err)
		}
		wc, err := wgconf.ParseFile(cp)
		if err != nil {
			return nil, fmt.Errorf("tunnel %q: %w", name, err)
		}
		p.Confs[name] = wc
		p.Hashes[name] = fmt.Sprintf("%x|%s|%s", sha256.Sum256(raw), t.Driver, t.Interface)
		ti := engine.TunnelInfo{Iface: t.Interface, HasV4: wc.HasIPv4(), HasV6: wc.HasIPv6()}
		for _, peer := range wc.Peers {
			ti.AllowedIPs = append(ti.AllowedIPs, peer.AllowedIPs...)
		}
		infos[name] = ti
	}
	p.Plan, err = engine.Compile(c, cgroupRoot, infos)
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
	} else if sys := dnsproxy.SystemUpstreams(); len(sys) > 0 {
		p.DNSUpstreams["direct"] = sys
	} else {
		p.Warnings = append(p.Warnings, "no DNS upstream for direct route: set dns.direct (system resolver is a loopback stub only)")
	}
	for name, t := range c.Tunnels {
		route := "tunnel:" + name
		if t.DNS != "" {
			u, _ := config.ParseUpstream(c.DNS.Upstream[t.DNS])
			p.DNSUpstreams[route] = []config.UpstreamSpec{u}
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
	d.tunnels = map[string]*tunnel.Tunnel{}
	d.specHash = map[string]string{}
	d.tunErrors = map[string]string{}

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
		Handler:     d.routes(),
		ConnContext: connContext,
	}
	go func() { _ = srv.Serve(ln) }()
	d.Log.Info("shuntd running", "socket", d.cfg.Daemon.Socket)

	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	hup := make(chan os.Signal, 1)
	notifyHUP(hup)
	for {
		select {
		case <-ctx.Done():
			_ = srv.Close()
			d.shutdown()
			return nil
		case <-hup:
			if err := d.reload(self); err != nil {
				d.Log.Error("reload failed, keeping previous state", "err", err)
			}
		case <-tick.C:
			d.watchdog()
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
	p, err := Prepare(d.ConfigPath, root)
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
	if err := d.proxy.Update(p.Plan, d.upstreams(p)); err != nil {
		return err
	}
	for _, w := range p.Warnings {
		d.Log.Warn(w)
	}
	d.cfg, d.plan, d.prep = p.Config, p.Plan, p
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
		t, err := tunnel.Up(tunnel.Spec{Name: name, Iface: tc.Interface, Driver: tc.Driver, Conf: p.Confs[name], Mark: engine.MarkBypass}, d.Log)
		if err != nil {
			d.Log.Error("tunnel up failed, its traffic stays blocked", "tunnel", name, "err", err)
			d.tunErrors[name] = err.Error()
			continue
		}
		d.tunnels[name] = t
		d.specHash[name] = p.Hashes[name]
		d.Log.Info("tunnel up", "tunnel", name, "iface", tc.Interface, "driver", t.Driver)
	}
	return routing.Sync(p.Plan, d.ifaceUp(p))
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
	d.tunnels = map[string]*tunnel.Tunnel{}
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

type credKey struct{}

func connContext(ctx context.Context, c net.Conn) context.Context {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return ctx
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return ctx
	}
	var cred *unix.Ucred
	_ = raw.Control(func(fd uintptr) {
		cred, _ = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if cred == nil {
		return ctx
	}
	return context.WithValue(ctx, credKey{}, cred)
}

func (d *Daemon) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, d.status())
	})
	mux.HandleFunc("POST /v1/run", func(w http.ResponseWriter, r *http.Request) {
		cred, _ := r.Context().Value(credKey{}).(*unix.Ucred)
		if cred == nil {
			writeErr(w, http.StatusForbidden, errors.New("no peer credentials"))
			return
		}
		var req api.RunRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		d.mu.Lock()
		g, ok := d.plan.Group(req.Group)
		d.mu.Unlock()
		if !ok {
			writeErr(w, http.StatusNotFound, fmt.Errorf("unknown group %q", req.Group))
			return
		}
		if err := d.cg.Move(g.Path, int(cred.Pid)); err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		d.Log.Info("process attached", "pid", cred.Pid, "uid", cred.Uid, "group", g.Name)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /v1/reload", func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		root := d.plan.CgroupRoot
		d.mu.Unlock()
		if err := d.reload(root); err != nil {
			writeErr(w, http.StatusUnprocessableEntity, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /v1/panic", func(w http.ResponseWriter, r *http.Request) {
		var req api.PanicRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
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
	st := api.Status{DefaultRoute: d.plan.DefaultRoute.String(), Panic: d.panic, Warnings: d.prep.Warnings, DNS: map[string][]string{}}
	for route, specs := range d.prep.DNSUpstreams {
		for _, s := range specs {
			st.DNS[route] = append(st.DNS[route], s.Proto+"://"+s.Addr.String())
		}
	}
	names := make([]string, 0, len(d.cfg.Tunnels))
	for n := range d.cfg.Tunnels {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		ts := api.TunnelStatus{Name: n, Iface: d.cfg.Tunnels[n].Interface, Error: d.tunErrors[n]}
		if t, ok := d.tunnels[n]; ok {
			ts.Up, ts.Driver = true, t.Driver
			ts.Peers, _ = t.Status()
		}
		st.Tunnels = append(st.Tunnels, ts)
	}
	for _, g := range d.plan.Groups {
		procs, _ := d.cg.Procs(g.Path)
		st.Groups = append(st.Groups, api.GroupStatus{Name: g.Name, Procs: len(procs)})
	}
	for _, r := range d.plan.Rules {
		st.Rules = append(st.Rules, fmt.Sprintf("%s -> %s", r.Name, r.Route))
	}
	return st
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
