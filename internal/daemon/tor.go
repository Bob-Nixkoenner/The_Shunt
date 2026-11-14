package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/Bob-Nixkoenner/the_shunt/internal/engine"
	"github.com/Bob-Nixkoenner/the_shunt/internal/procapp"
	"github.com/Bob-Nixkoenner/the_shunt/internal/socks"
	"github.com/Bob-Nixkoenner/the_shunt/internal/tunnel"
)

// torDial returns the function that opens a connection through tor for
// the tunnel name: SOCKS5 to tor's socket, the user name being the app that
// asked (isolate = "app"). The user name is the key of the rule (see Update),
// so the isolation is per rule: apps of one rule share circuits.
func (d *Daemon) torDial(name, isolate string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		d.mu.Lock()
		ts, ok := d.tunnels[name].(tunnel.TorStatus)
		d.mu.Unlock()
		if !ok {
			return nil, errors.New("tor is not running")
		}
		user := ""
		if isolate == "app" {
			if user = socks.UserOf(ctx); user == "" {
				user = "app:" + appOf(socks.ClientAddr(ctx))
			}
		}
		return socks.DialVia(ctx, "unix", ts.SocksPath(), user, addr)
	}
}

// newIdentity makes the Tor tunnel build fresh circuits.
func (d *Daemon) newIdentity(name string) error {
	d.mu.Lock()
	t, ok := d.tunnels[name]
	cfg := d.cfg.Tunnels[name]
	d.mu.Unlock()
	if !cfg.IsTor() {
		return fmt.Errorf("%q is not a Tor tunnel", name)
	}
	ts, ok2 := t.(tunnel.TorStatus)
	if !ok || !ok2 {
		return fmt.Errorf("tunnel %q is not running", name)
	}
	return ts.NewIdentity()
}

func appOf(a net.Addr) string {
	if ta, ok := a.(*net.TCPAddr); ok {
		if ap, ok := netip.AddrFromSlice(ta.IP); ok {
			return procapp.TCP(netip.AddrPortFrom(ap.Unmap(), uint16(ta.Port)))
		}
	}
	return procapp.Unknown
}

// loopbackGuard sets the loopback guard (Linux: nft table shunt_torguard).
type loopbackGuard interface {
	GuardLoopback(g LoopbackGuard) error
}

// LoopbackGuard is what the loopback guard enforces. An empty one lifts it.
type LoopbackGuard struct {
	// TorPorts and Socks are dropped: loopback ports a Tor proxy listener
	// could not bind and SOCKS exit addresses another program holds; the
	// Tor traffic and the traffic of programs set up for the exit must not
	// reach that program (report M-04).
	TorPorts []int
	Socks    []netip.AddrPort
	// Exits are the running SOCKS exits: held and blocked programs (Plan)
	// and, with Users, other users may not use them (report M-06).
	Exits []ExitUsers
	Plan  *engine.Plan
}

// ExitUsers is one running SOCKS exit and the users allowed on it.
type ExitUsers struct {
	Addr  netip.AddrPort
	Users bool     // socks_users set: only UIDs (an empty list: nobody)
	UIDs  []uint32 // resolved socks_users
}

// lookupUID resolves a user name or numeric UID.
var lookupUID = func(name string) (uint32, error) {
	if n, err := strconv.ParseUint(name, 10, 32); err == nil {
		return uint32(n), nil
	}
	u, err := user.Lookup(name)
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseUint(u.Uid, 10, 32)
	return uint32(n), err
}

// exitUsers lists the exits the manager runs (states) with their allowed
// users. A name that does not resolve is left out and logged: the exit
// stays closed to it (and, if none resolves, to everybody).
func (d *Daemon) exitUsers(c *config.Config, states map[string]string) []ExitUsers {
	names := make([]string, 0, len(states))
	for n, st := range states {
		if st == socks.StateListening {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	var out []ExitUsers
	for _, n := range names {
		t, ok := c.Tunnels[n]
		if !ok {
			continue
		}
		ap, err := netip.ParseAddrPort(t.Socks)
		if err != nil {
			continue
		}
		e := ExitUsers{Addr: ap, Users: len(t.SocksUsers) > 0}
		for _, u := range t.SocksUsers {
			uid, err := lookupUID(u)
			if err != nil {
				d.Log.Error("socks_users: unknown user, not allowed on the exit", "tunnel", n, "user", u, "err", err)
				continue
			}
			e.UIDs = append(e.UIDs, uid)
		}
		out = append(out, e)
	}
	return out
}

// torProxy runs the transparent listener of every Tor route: nft redirects
// the route's TCP there (127.0.0.1 and ::1 only).
type torProxy struct {
	mu   sync.Mutex
	runs map[int][]net.Listener // proxy port -> listeners
}

// Update binds the listeners of the plan's Tor routes and returns the proxy
// ports it could not bind because something else holds them (report M-04:
// the ports are fixed and above 1024, so any local user can take one first;
// nft would then redirect Tor traffic to that user's listener in plain
// text). The caller blocks those ports (fail closed).
func (t *torProxy) Update(pp *Prepared, dial func(name, isolate string) func(context.Context, string, string) (net.Conn, error)) (taken []int) {
	p := pp.Plan
	// port -> route, and the isolation key of the rule behind a port ("" =
	// the program, see torDial)
	type target struct {
		r   *engine.Route
		key string
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.runs == nil {
		t.runs = map[int][]net.Listener{}
	}
	want := map[int]target{}
	for _, r := range p.Routes {
		if r.Kind == config.RouteTunnel && r.Tor {
			want[r.ProxyPort] = target{r, ""}
		}
	}
	for _, ru := range p.Rules {
		if ru.ProxyPort != 0 && ru.Route != nil && ru.Route.Tor {
			want[ru.ProxyPort] = target{ru.Route, "rule:" + ru.Name}
		}
	}
	for port, ls := range t.runs {
		if _, ok := want[port]; !ok {
			for _, l := range ls {
				_ = l.Close()
			}
			delete(t.runs, port)
		}
	}
	for port, tg := range want {
		r, key := tg.r, tg.key
		if _, ok := t.runs[port]; ok {
			continue
		}
		var ls []net.Listener
		inUse := false
		for _, host := range []string{"127.0.0.1", "::1"} {
			l, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
			if err != nil {
				if errors.Is(err, syscall.EADDRINUSE) {
					inUse = true // someone else listens there: never let traffic reach it
				}
				continue // no IPv6 on loopback: fine
			}
			ls = append(ls, l)
			name, isolate := r.Tunnel, pp.Config.Tunnels[r.Tunnel].Isolate
			tp := &socks.Transparent{Handle: func(ctx context.Context, c net.Conn, dst netip.AddrPort) {
				ctx = socks.WithClientAddr(ctx, c.RemoteAddr())
				if key != "" && isolate == "app" {
					ctx = socks.WithUser(ctx, key)
				}
				out, err := dial(name, isolate)(ctx, "tcp", dst.String())
				if err != nil {
					c.Close()
					return
				}
				socks.Pipe(c, out)
			}}
			go func() { _ = tp.Serve(l) }()
		}
		if inUse {
			for _, l := range ls {
				_ = l.Close()
			}
			taken = append(taken, port) // tried again with the next plan
			continue
		}
		t.runs[port] = ls
	}
	sort.Ints(taken)
	return taken
}

// Close stops every listener.
func (t *torProxy) Close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for port, ls := range t.runs {
		for _, l := range ls {
			_ = l.Close()
		}
		delete(t.runs, port)
	}
}

// torAllFile keeps the switch across restarts: after a restart or reboot
// everything must not silently go back to the old routes.
func (d *Daemon) torAllFile() string { return filepath.Join(filepath.Dir(d.ConfigPath), "tor-all") }

// loadTorAll returns the tunnel of the tor-all switch ("" = off). Called with
// d.mu held (reload).
func (d *Daemon) loadTorAll() string {
	if !d.torLoad {
		d.torLoad = true
		if b, err := os.ReadFile(d.torAllFile()); err == nil {
			d.torAll = strings.TrimSpace(string(b))
		}
	}
	return d.torAll
}

// setTorAll switches "everything through Tor" on (for tunnel, or the only
// Tor tunnel) or off, and applies it.
func (d *Daemon) setTorAll(on bool, tunnelName string) error {
	d.mu.Lock()
	cfg := d.cfg
	d.mu.Unlock()
	name := ""
	if on {
		var tors []string
		for n, t := range cfg.Tunnels {
			if t.IsTor() && !t.Disabled {
				tors = append(tors, n)
			}
		}
		sort.Strings(tors)
		switch {
		case tunnelName != "":
			if t, ok := cfg.Tunnels[strings.TrimPrefix(tunnelName, "tunnel:")]; !ok || !t.IsTor() || t.Disabled {
				return fmt.Errorf("%q is not an enabled Tor tunnel", tunnelName)
			}
			name = strings.TrimPrefix(tunnelName, "tunnel:")
		case len(tors) == 1:
			name = tors[0]
		case len(tors) == 0:
			return errors.New("there is no Tor tunnel: add one first (Configure → Add a tunnel → Tor)")
		default:
			return fmt.Errorf("more than one Tor tunnel (%s): name one", strings.Join(tors, ", "))
		}
	}
	if on {
		if _, ok := d.Backend.(Emergencer); ok {
			tc := cfg.Tunnels[name]
			if tc.Via != "" {
				return fmt.Errorf("tor-all: the Tor tunnel %q runs through another tunnel (via), which the strict mode cannot follow", name)
			}
			// without a relay list or bridges, tor could never start once
			// everything else is shut
			if _, _, err := emergencyDsts(name, tc); err != nil {
				return fmt.Errorf("tor-all: Tor must know its relays first (%v): run Tor once without tor-all, or configure bridges", err)
			}
		}
	}
	d.mu.Lock()
	old, oldLoad := d.torAll, d.torLoad
	d.torAll, d.torLoad = name, true
	d.mu.Unlock()
	if err := d.saveTorAll(name); err != nil {
		return err
	}
	if err := d.reload(d.selfCgroup()); err != nil {
		d.mu.Lock()
		d.torAll, d.torLoad = old, oldLoad
		d.mu.Unlock()
		_ = d.saveTorAll(old)
		return err
	}
	d.Log.Warn("tor-all", "on", on, "tunnel", name)
	return nil
}

func (d *Daemon) saveTorAll(name string) error {
	if name == "" {
		if err := os.Remove(d.torAllFile()); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	return os.WriteFile(d.torAllFile(), []byte(name+"\n"), 0o644)
}
