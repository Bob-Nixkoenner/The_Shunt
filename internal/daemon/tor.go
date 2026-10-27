package daemon

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
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
			user = "app:" + appOf(socks.ClientAddr(ctx))
		}
		return socks.DialVia(ctx, "unix", ts.SocksPath(), user, addr)
	}
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
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.runs == nil {
		t.runs = map[int][]net.Listener{}
	}
	want := map[int]*engine.Route{}
	for _, r := range p.Routes {
		if r.Kind == config.RouteTunnel && r.Tor {
			want[r.ProxyPort] = r
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
	for port, r := range want {
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
