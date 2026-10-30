package splitstack

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/health"
	"github.com/Bob-Nixkoenner/the_shunt/internal/socks"
)

// A Tor tunnel sends TCP to a Tor client's SOCKS5 port and names to its
// DNSPort. The Tor client is not part of this library: on Android it is
// Orbot (SOCKS 127.0.0.1:9050) or the Tor the app brings along. Names are
// resolved through the SOCKS port (Tor's RESOLVE), or sent to the DNSPort when
// "dns" is given (Orbot's DNSPort is random). UDP (except DNS) and ICMP are
// refused, as on Linux.
//
// The file (Conf) is two lines, both optional:
//
//	socks = 127.0.0.1:9050
//	dns   = 127.0.0.1:5400   (only if the client has a fixed DNSPort)
//	client = builtin         (the Tor the app brings; socks/dns are then chosen by the app)
//	bridge = snowflake       (builtin only; obfs4 | snowflake | meek or a bridge line, repeatable)

const typeTor = "tor"

// torDNS is the "DNS server of the tunnel" the stack asks: queries to it are
// handed to Tor's DNSPort. It is never put on a network.
var torDNS = netip.MustParseAddr("10.111.0.54")

// torUser is the SOCKS user name: Tor gives each different one its own circuits.
const torUser = "shunt"

type torConf struct {
	Socks, DNS string
	// Builtin: run the Tor the app brings (torProc) instead of talking to Orbot.
	Builtin bool
	// Bridges: shorthands ("obfs4", "snowflake", "meek") or bridge lines (builtin Tor only).
	Bridges []string
}

func parseTorConf(s string) (torConf, error) {
	c := torConf{Socks: "127.0.0.1:9050"}
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			return c, fmt.Errorf("tor: line %q is not key = value", l)
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "client":
			switch v {
			case "builtin":
				c.Builtin = true
			case "orbot", "external":
				c.Builtin = false
			default:
				return c, fmt.Errorf("tor: client = %q (builtin | orbot)", v)
			}
			continue
		case "bridge":
			c.Bridges = append(c.Bridges, v)
			continue
		}
		if _, err := netip.ParseAddrPort(v); err != nil || !netip.MustParseAddrPort(v).Addr().IsLoopback() {
			return c, fmt.Errorf("tor: %s = %q must be a loopback address with a port (127.0.0.1:9050)", k, v)
		}
		switch k {
		case "socks":
			c.Socks = v
		case "dns":
			c.DNS = v
		default:
			return c, fmt.Errorf("tor: unknown key %q (client | socks | dns | bridge)", k)
		}
	}
	return c, nil
}

type torTunnel struct {
	conf torConf
	proc *torProc // builtin Tor, nil for Orbot

	mu      sync.Mutex
	checked time.Time
	alive   bool
	rx, tx  int64

	onion   map[netip.Addr]string // address handed out -> onion name
	onionBy map[string]netip.Addr
	onionN  int
}

func newTorTunnel(conf string) (*torTunnel, error) {
	c, err := parseTorConf(conf)
	if err != nil {
		return nil, err
	}
	return &torTunnel{conf: c}, nil
}

// startBuiltin runs the Tor the app brings and points the tunnel at it.
func (t *torTunnel) startBuiltin(exe, pt, dir string, logf func(string, ...any)) error {
	if exe == "" || dir == "" {
		return errors.New("this build has no built-in Tor (use Orbot)")
	}
	p, err := startTorProc(exe, dir, t.conf.Bridges, pt, logf)
	if err != nil {
		return err
	}
	t.proc = p
	t.conf.Socks = p.Socks()
	return nil
}

func (t *torTunnel) close() {
	if t.proc != nil {
		t.proc.Close()
	}
}

// reachable: something listens on the SOCKS port (checked at most every 3 s).
func (t *torTunnel) reachable() bool {
	if t.proc != nil && t.proc.Bootstrap() < 100 {
		return false // not through the network yet: its apps wait (blocked), no direct fallback
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if time.Since(t.checked) < 3*time.Second {
		return t.alive
	}
	c, err := net.DialTimeout("tcp", t.conf.Socks, time.Second)
	if err == nil {
		c.Close()
	}
	t.alive, t.checked = err == nil, time.Now()
	return t.alive
}

func (t *torTunnel) dial(ctx context.Context, tcp bool, ap netip.AddrPort) (net.Conn, error) {
	if !tcp {
		if ap.Addr() == torDNS && ap.Port() == 53 {
			if t.conf.DNS == "" {
				return newTorResolver(t), nil
			}
			var d net.Dialer
			return d.DialContext(ctx, "udp", t.conf.DNS)
		}
		return nil, errors.New("Tor carries TCP only (no UDP, no calls)")
	}
	if ap.Addr() == torDNS {
		return nil, errors.New("no TCP to the Tor DNS address")
	}
	user := torUser
	if u := socks.UserOf(ctx); u != "" {
		user = u
	}
	target := ap.String()
	if name, ok := t.onionName(ap.Addr()); ok {
		target = net.JoinHostPort(name, fmt.Sprint(ap.Port()))
	}
	c, err := socks.DialVia(ctx, "tcp", t.conf.Socks, user, target)
	if err != nil {
		return nil, err
	}
	return &countConn{Conn: c, t: t}, nil
}

// dialName connects to "host:port" through Tor with the name unresolved.
func (t *torTunnel) dialName(ctx context.Context, addr string) (net.Conn, error) {
	if !t.reachable() {
		return nil, errors.New("Tor is not running")
	}
	c, err := socks.DialVia(ctx, "tcp", t.conf.Socks, torUser, addr)
	if err != nil {
		return nil, err
	}
	return &countConn{Conn: c, t: t}, nil
}

type countConn struct {
	net.Conn
	t *torTunnel
}

func (c *countConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.t.mu.Lock()
	c.t.rx += int64(n)
	c.t.mu.Unlock()
	return n, err
}

func (c *countConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.t.mu.Lock()
	c.t.tx += int64(n)
	c.t.mu.Unlock()
	return n, err
}

func (t *torTunnel) status(name string) tunnelStatus {
	st := tunnelStatus{Name: name, Type: typeTor}
	st.Up = t.reachable()
	t.mu.Lock()
	st.RX, st.TX = t.rx, t.tx
	t.mu.Unlock()
	if t.proc != nil {
		st.Bootstrap = t.proc.Bootstrap()
		if st.Bootstrap == 0 {
			st.Bootstrap = 1 // "starting" is visible even before the first answer
		}
	}
	if st.Up {
		st.Health = health.Report{State: health.OK, HandshakeAge: -1} // Tor has no handshake: "reachable and through the network" is the whole health
	} else if t.proc != nil {
		if e := t.proc.Err(); e != "" {
			st.Error = fmt.Sprintf("Tor failed (%d %%): %s", t.proc.Bootstrap(), e) // the reason, not just "starting"
		} else {
			st.Error = fmt.Sprintf("Tor is starting: %d %%", t.proc.Bootstrap())
		}
		st.Health = health.Report{State: health.Down, HandshakeAge: -1}
	} else {
		st.Error = "no Tor client answers on " + t.conf.Socks + " (start Orbot)"
		st.Health = health.Report{State: health.Down, HandshakeAge: -1}
	}
	return st
}

func (e *Engine) newTorWT(tc tunnelConf) (*wgTunnel, error) {
	t := &wgTunnel{name: tc.Name, torType: true, ovpnConf: tc}
	tt, err := newTorTunnel(tc.Conf)
	if err != nil {
		return t, err
	}
	if tt.conf.Builtin {
		if err := tt.startBuiltin(e.torExe, e.ptExe, filepath.Join(e.workDir, "tor", tc.Name), func(f string, a ...any) { e.logf("tunnel "+tc.Name+": "+f, a...) }); err != nil {
			return t, err
		}
	}
	t.tor = tt
	return t, nil
}

// torWaitMax is how long a leak test waits for a Tor that is still starting; torPoll the step.
var (
	torWaitMax = 90 * time.Second
	torPoll    = 500 * time.Millisecond
)

// waitReady waits (up to max, or until ctx ends) until the built-in Tor is
// through the network and returns its progress (100 = ready). A Tor from
// Orbot has no progress: it is "ready" when its SOCKS port answers.
func (t *torTunnel) waitReady(ctx context.Context, max time.Duration) int {
	if t.proc == nil {
		return 100
	}
	end := time.Now().Add(max)
	for {
		if n := t.proc.Bootstrap(); n >= 100 || !time.Now().Before(end) {
			return n
		}
		select {
		case <-ctx.Done():
			return t.proc.Bootstrap()
		case <-time.After(torPoll):
		}
	}
}

// Start asks the built-in Tor to start now (it waits a few seconds after a failure).
func (t *torTunnel) Start() {
	if t.proc != nil {
		t.proc.Kick()
	}
}

// CheckTor validates the file of a Tor tunnel for the app: JSON with "socks"
// and "dns" (the addresses in use).
func CheckTor(conf string) (string, error) {
	c, err := parseTorConf(conf)
	if err != nil {
		return "", err
	}
	m := map[string]string{"socks": c.Socks}
	if c.Builtin {
		delete(m, "socks") // chosen by the app at start
		m["client"] = "builtin"
		if len(c.Bridges) > 0 {
			m["bridges"] = strings.Join(c.Bridges, " | ")
		}
	}
	if c.DNS != "" {
		m["dns"] = c.DNS
	}
	b, _ := json.Marshal(m)
	return string(b), nil
}
