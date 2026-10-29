package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/Bob-Nixkoenner/the_shunt/internal/engine"
	"github.com/Bob-Nixkoenner/the_shunt/internal/procapp"
	"github.com/Bob-Nixkoenner/the_shunt/internal/socks"
	"github.com/Bob-Nixkoenner/the_shunt/internal/tunnel"
)

// torDial returns the function that opens a connection through tor for
// the tunnel name: SOCKS5 to tor's socket, the user name being the app that
// asked (isolate = "app"), so every app gets its own circuits.
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

// torProxy runs the transparent listener of every Tor route: nft redirects
// the route's TCP there (127.0.0.1 and ::1 only).
type torProxy struct {
	mu   sync.Mutex
	runs map[int][]net.Listener // proxy port -> listeners
}

func (t *torProxy) Update(pp *Prepared, dial func(name, isolate string) func(context.Context, string, string) (net.Conn, error)) {
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
		for _, host := range []string{"127.0.0.1", "::1"} {
			l, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
			if err != nil {
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
		t.runs[port] = ls
	}
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
