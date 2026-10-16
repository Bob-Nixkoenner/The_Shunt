//go:build !android

package splitstack

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/tsconf"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tsnet"
)

// Tailscale/Headscale tunnels run tailscale's own userspace client (tsnet)
// inside the service: no adapter, no routes on the machine. For the rest of
// the split stack they look like WireGuard tunnels (dial TCP/UDP through
// them, health, statistics).

const typeTailscale = "tailscale"

// tailnet4 is where a tunnel without an exit node may go. Everything else
// would leave through the normal network (tsnet falls back to the system
// dialer for addresses no peer routes), which must never happen here.
var tailnet4 = netip.MustParsePrefix("100.64.0.0/10")

// tsDNS is the resolver every tailscale node has (MagicDNS, and the DNS
// servers of the tailnet, through the exit node if there is one).
var tsDNS = netip.MustParseAddr("100.100.100.100")

type tsTunnel struct {
	name string
	conf *tsconf.Config
	srv  *tsnet.Server
	logf func(string, ...any)

	cancel context.CancelFunc
	done   chan struct{}

	mu        sync.Mutex
	running   bool // backend Running
	exitReady bool // exit node chosen and online (always true without exit_node)
	err       string
	rx, tx    int64
	handshake time.Time
}

// startTailscale starts tsnet in dir (state, kept between runs) and returns
// at once; joining the tailnet and choosing the exit node go on in the
// background (Status shows how far it is).
func startTailscale(name, conf, dir string, logf func(string, ...any)) (*tsTunnel, error) {
	c, err := tsconf.Parse(conf)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	host := c.Hostname
	if host == "" {
		host = "shunt-" + strings.ToLower(name)
	}
	srv := &tsnet.Server{
		Dir:        filepath.Clean(dir),
		Hostname:   host,
		AuthKey:    c.AuthKey,
		ControlURL: c.LoginServer,
		Logf:       func(string, ...any) {},
		UserLogf:   func(f string, a ...any) { logf("tunnel "+name+": "+f, a...) },
	}
	if err := srv.Start(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	t := &tsTunnel{name: name, conf: c, srv: srv, logf: logf, cancel: cancel, done: make(chan struct{}), exitReady: c.ExitNode == ""}
	go t.run(ctx)
	return t, nil
}

// run joins the tailnet, picks the exit node and keeps the state fresh.
func (t *tsTunnel) run(ctx context.Context) {
	defer close(t.done)
	lc, err := t.srv.LocalClient()
	if err != nil {
		t.setErr(err.Error())
		return
	}
	for ctx.Err() == nil {
		upCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		_, err := t.srv.Up(upCtx)
		cancel()
		if err == nil {
			break
		}
		t.setErr("cannot join the tailnet: " + err.Error())
		select {
		case <-ctx.Done():
			return
		case <-time.After(15 * time.Second):
		}
	}
	tick := time.NewTicker(3 * time.Second)
	defer tick.Stop()
	for {
		sctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		st, err := lc.Status(sctx)
		cancel()
		if err == nil {
			t.update(ctx, lc, st)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (t *tsTunnel) update(ctx context.Context, lc interface {
	EditPrefs(context.Context, *ipn.MaskedPrefs) (*ipn.Prefs, error)
}, st *ipnstate.Status) {
	running := st.BackendState == "Running"
	var rx, tx int64
	var hs time.Time
	for _, p := range st.Peer {
		rx += p.RxBytes
		tx += p.TxBytes
		if p.LastHandshake.After(hs) {
			hs = p.LastHandshake
		}
	}
	exitReady := t.conf.ExitNode == ""
	if running && t.conf.ExitNode != "" {
		if want := exitNodePrefs(t.conf.ExitNode, st); want != nil && (st.ExitNodeStatus == nil || st.ExitNodeStatus.ID != want.Prefs.ExitNodeID) {
			ectx, cancel := context.WithTimeout(ctx, 5*time.Second)
			_, err := lc.EditPrefs(ectx, want)
			cancel()
			if err != nil {
				t.setErr("exit node: " + err.Error())
			} else {
				t.logf("tunnel %s: exit node %s", t.name, t.conf.ExitNode)
			}
		}
		exitReady = st.ExitNodeStatus != nil && st.ExitNodeStatus.Online
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.running, t.exitReady, t.rx, t.tx = running, exitReady, rx, tx
	if running && exitReady {
		t.err = ""
	}
	if !hs.IsZero() {
		t.handshake = hs
	} else if running && exitReady && t.handshake.IsZero() {
		t.handshake = time.Now()
	}
}

// exitNodePrefs selects the exit node by tailnet address or by node name; nil
// while the node is not in the netmap yet.
func exitNodePrefs(want string, st *ipnstate.Status) *ipn.MaskedPrefs {
	if a, err := netip.ParseAddr(want); err == nil {
		for _, p := range st.Peer {
			for _, ip := range p.TailscaleIPs {
				if ip == a && p.ExitNodeOption {
					return &ipn.MaskedPrefs{Prefs: ipn.Prefs{ExitNodeID: p.ID}, ExitNodeIDSet: true, ExitNodeIPSet: true}
				}
			}
		}
		return nil
	}
	for _, p := range st.Peer {
		name := strings.TrimSuffix(strings.SplitN(p.DNSName, ".", 2)[0], ".")
		if p.ExitNodeOption && (strings.EqualFold(p.HostName, want) || strings.EqualFold(name, want)) {
			return &ipn.MaskedPrefs{Prefs: ipn.Prefs{ExitNodeID: p.ID}, ExitNodeIDSet: true, ExitNodeIPSet: true}
		}
	}
	return nil
}

func (t *tsTunnel) setErr(s string) {
	t.mu.Lock()
	t.err = s
	t.mu.Unlock()
}

// dial opens a connection through the tunnel; "tcp" or "udp".
func (t *tsTunnel) dial(ctx context.Context, network string, ap netip.AddrPort) (net.Conn, error) {
	t.mu.Lock()
	running, exitReady := t.running, t.exitReady
	t.mu.Unlock()
	if !running {
		return nil, errors.New("tailscale tunnel is not connected")
	}
	if !tailnet4.Contains(ap.Addr().Unmap()) {
		if t.conf.ExitNode == "" {
			return nil, fmt.Errorf("tunnel %s has no exit node: only the tailnet (100.64.0.0/10) is reachable", t.name)
		}
		if !exitReady {
			return nil, fmt.Errorf("tunnel %s: exit node %s is not ready", t.name, t.conf.ExitNode)
		}
	}
	return t.srv.Dial(ctx, network, ap.String())
}

// status: connected, byte counters, last handshake, last problem.
func (t *tsTunnel) status() (up bool, rx, tx int64, hs time.Time, err string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.running && t.exitReady, t.rx, t.tx, t.handshake, t.err
}

func (t *tsTunnel) close() {
	t.cancel()
	t.srv.Close()
	<-t.done
}
