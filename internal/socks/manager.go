package socks

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"sync"
)

// Exit is one tunnel's SOCKS listener.
type Exit struct {
	Listen  string // 127.0.0.1:1080
	Mark    uint32
	Resolve func(ctx context.Context, name string) ([]netip.Addr, error)
	// Dial replaces the marked dialer (Tor: through tor's SOCKS socket); it
	// gets names unresolved, and there is no UDP.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Manager keeps one listener per tunnel with a socks address.
type Manager struct {
	Log *slog.Logger

	mu   sync.Mutex
	runs map[string]*run
}

type run struct {
	exit Exit
	l    net.Listener
	srv  *Server
}

// Update starts, restarts and stops listeners so they match exits (tunnel
// name -> exit). A listener that cannot bind is logged; the others go on.
//
// It returns the listen addresses another program already holds (report
// M-04): programs set up to use the exit would talk to that program's
// listener instead, in plain text and outside the tunnel. The caller blocks
// them (fail closed); a free address is bound on the next Update.
func (m *Manager) Update(exits map[string]Exit) (taken []netip.AddrPort) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.runs == nil {
		m.runs = map[string]*run{}
	}
	for name, r := range m.runs {
		if e, ok := exits[name]; !ok || e.Listen != r.exit.Listen || e.Mark != r.exit.Mark || (e.Dial == nil) != (r.exit.Dial == nil) {
			r.stop()
			delete(m.runs, name)
		}
	}
	for name, e := range exits {
		if r, ok := m.runs[name]; ok {
			r.srv.SetResolve(e.Resolve)
			continue
		}
		l, err := net.Listen("tcp", e.Listen)
		if err != nil {
			if addrInUse(err) {
				if ap, perr := netip.ParseAddrPort(e.Listen); perr == nil {
					taken = append(taken, ap)
				}
				m.Log.Error("SOCKS EXIT ADDRESS TAKEN BY ANOTHER PROGRAM: not handed over", "tunnel", name, "listen", e.Listen, "err", err)
				continue
			}
			m.Log.Warn("socks exit", "tunnel", name, "listen", e.Listen, "err", err)
			continue
		}
		srv := &Server{Dial: MarkedDialer(e.Mark), ListenPacket: MarkedListenPacket(e.Mark), Resolve: e.Resolve, Log: m.Log}
		if e.Dial != nil {
			srv = &Server{Dial: e.Dial, Remote: true, Log: m.Log}
		}
		go func() { _ = srv.Serve(l) }()
		m.runs[name] = &run{exit: e, l: l, srv: srv}
		m.Log.Info("socks exit", "tunnel", name, "listen", e.Listen)
	}
	sort.Slice(taken, func(i, j int) bool { return taken[i].Compare(taken[j]) < 0 })
	return taken
}

// Addrs returns tunnel name -> listen address.
func (m *Manager) Addrs() map[string]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]string{}
	for n, r := range m.runs {
		out[n] = r.exit.Listen
	}
	return out
}

// Close stops every listener and drops open connections.
func (m *Manager) Close() { m.Update(nil) }

func (r *run) stop() {
	_ = r.l.Close()
	r.srv.CloseConns()
}
