package splitstack

import (
	"encoding/json"
	"errors"
	"net/netip"
	"path/filepath"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/health"
	"github.com/Bob-Nixkoenner/the_shunt/internal/ovpnconf"
	"github.com/Bob-Nixkoenner/the_shunt/internal/ovpndroid"
)

// OpenVPN tunnels run the openvpn program in its Android mode behind a
// netstack (internal/ovpndroid); for the rest of the split stack they look
// like WireGuard tunnels: same Net to dial, DNS, health, statistics.

const (
	typeWireGuard = "wireguard"
	typeOpenVPN   = "openvpn"
)

// ovpnRestartGap: at most one restart of an ended openvpn per gap (a var
// for the tests).
var ovpnRestartGap = 30 * time.Second

// checkOpenVPN cleans a .ovpn file (scripts, management, … removed, see
// internal/ovpnconf) and checks it can run here: a client config with
// everything inline, no files next to it.
func checkOpenVPN(conf string) (clean string, c *ovpnconf.Config, err error) {
	clean, _ = ovpnconf.Sanitize(conf)
	c, err = ovpnconf.Parse(clean, "")
	if err != nil {
		return "", nil, err
	}
	if len(c.Files) > 0 {
		return "", nil, errors.New("refers to files (" + filepath.Base(c.Files[0]) + "): put certificates and keys inline (<ca>…</ca>)")
	}
	if len(c.Remotes) == 0 {
		return "", nil, errors.New("no remote (server) in the file")
	}
	return clean, c, nil
}

func (e *Engine) newOVPNTunnel(tc tunnelConf, mtu int) (*wgTunnel, error) {
	if e.ovpnExe == "" || e.workDir == "" {
		return nil, errors.New("OpenVPN is not available on this platform")
	}
	clean, c, err := checkOpenVPN(tc.Conf)
	if err != nil {
		return nil, err
	}
	if c.NeedsAuth && tc.User == "" {
		return nil, errors.New("needs a username and password")
	}
	t := &wgTunnel{name: tc.Name, ovpnConf: tc, ovpnClean: clean, mtu: mtu}
	if tc.Via != "" {
		outer := e.tunnels[tc.Via]
		if outer == nil || outer.isOVPN() {
			return nil, errors.New("via: " + tc.Via + " is not a WireGuard tunnel here")
		}
		if outer.net == nil {
			return nil, errors.New("via: tunnel " + tc.Via + " is not up")
		}
		if t.ovpnClean, t.via, err = viaRewrite(clean, outer.net.DialContext); err != nil {
			return nil, err
		}
	}
	return t, e.startOVPN(t)
}

func (e *Engine) startOVPN(t *wgTunnel) error {
	t.ovpnStarted = time.Now()
	ot, err := ovpndroid.Start(ovpndroid.Options{
		Exe: e.ovpnExe, Config: t.ovpnClean, Dir: filepath.Join(e.workDir, "openvpn", t.name),
		User: t.ovpnConf.User, Pass: t.ovpnConf.Pass, MTU: t.mtu,
		Logf: func(f string, a ...any) { e.logf("tunnel "+t.name+": "+f, a...) },
	})
	if err != nil {
		return err
	}
	t.ovpnMu.Lock()
	t.ovpn = ot
	t.ovpnMu.Unlock()
	return nil
}

// ovpnTunnel returns the running openvpn (nil for WireGuard tunnels).
func (t *wgTunnel) ovpnTunnel() *ovpndroid.Tunnel {
	t.ovpnMu.Lock()
	defer t.ovpnMu.Unlock()
	return t.ovpn
}

// ovpnRestart starts openvpn again if it ended (crash, server gone for
// good, fatal error); called by the health loop.
func (e *Engine) ovpnRestart(t *wgTunnel, now time.Time) {
	ot := t.ovpnTunnel()
	if ot == nil {
		return
	}
	select {
	case <-ot.Done():
	default:
		return
	}
	if now.Sub(t.ovpnStarted) < ovpnRestartGap {
		return
	}
	e.logf("tunnel %s: openvpn ended (%v), restarting", t.name, ot.Err())
	if err := e.startOVPN(t); err != nil {
		e.logf("tunnel %s: %v", t.name, err)
	}
}

func (t *wgTunnel) ovpnStatus() (st tunnelStatus) {
	ot := t.ovpnTunnel()
	st = tunnelStatus{Name: t.name, Type: typeOpenVPN, Via: t.ovpnConf.Via, Error: t.err}
	if ot == nil {
		st.Health = health.Report{State: health.Down, HandshakeAge: -1}
		return st
	}
	defer func() { st.Health = t.mon.Report(time.Now()) }()
	select {
	case <-ot.Done():
		if err := ot.Err(); err != nil {
			st.Error = err.Error()
		}
		return st
	default:
	}
	st.Up = ot.Connected()
	st.RX, st.TX = ot.Bytes()
	// openvpn has no handshake time; it keeps the link alive itself (ping,
	// ping-restart), so "connected" counts as a fresh handshake.
	if st.Up {
		st.Handshake = time.Now().Unix()
	}
	return st
}

// ovpnDNS is the DNS server pushed by the server, 1.1.1.1 (through the
// tunnel) if none.
func ovpnDNS(ot *ovpndroid.Tunnel) netip.Addr {
	for _, a := range ot.DNS() {
		if a.Is4() {
			return a
		}
	}
	if d := ot.DNS(); len(d) > 0 {
		return d[0]
	}
	return netip.MustParseAddr("1.1.1.1")
}

// CheckOpenVPN validates a .ovpn file (import in an app) and returns a short
// JSON summary: servers, whether it needs a username/password, and what was
// removed (scripts and the like, which never run here).
func CheckOpenVPN(conf string) (string, error) {
	clean, c, err := checkOpenVPN(conf)
	if err != nil {
		return "", err
	}
	_, removed := ovpnconf.Sanitize(conf)
	sum := struct {
		Remotes   []string `json:"remotes"`
		NeedsAuth bool     `json:"needs_auth"`
		Removed   []string `json:"removed"`
		Clean     string   `json:"clean"`
	}{c.Remotes, c.NeedsAuth, removed, clean}
	b, _ := json.Marshal(sum)
	return string(b), nil
}

func (e *Engine) newTSTunnel(tc tunnelConf) (*wgTunnel, error) {
	if e.workDir == "" {
		return nil, errors.New("Tailscale is not available here (no work folder)")
	}
	t := &wgTunnel{name: tc.Name, tsType: true, ovpnConf: tc}
	ts, err := startTailscale(tc.Name, tc.Conf, filepath.Join(e.workDir, "tailscale", tc.Name), e.logf)
	if err != nil {
		return t, err
	}
	t.ts = ts
	return t, nil
}
