package splitstack

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/tunnel"
)

// torProc is the Tor the app brings along (libtor.so from tor-android, a
// program in the app's library folder, started like openvpn). It listens on
// loopback ports chosen at start, is told apart from other programs by a
// cookie file, and is restarted when it ends. The SOCKS port keeps Tor's
// default IsolateSOCKSAuth: each SOCKS user name gets its own circuits.
type torProc struct {
	exe, dir string
	bridges  []string
	pt       string // lyrebird ("" = none)
	logf     func(string, ...any)

	socksPort, ctlPort int

	mu        sync.Mutex
	proc      *os.Process
	lastErr   string
	errRun    bool   // tor wrote an [err] line in this run
	lastLine  string // the last line tor wrote to stderr (any level): the reason when it dies without an [err]
	bootstrap int
	newnymAt  time.Time          // last NEWNYM: circuits from before do not count
	circAt    time.Time          // when circ was asked
	circ      *tunnel.TorCircuit // cached for a few seconds (the status polls)
	kick      chan struct{}
	stopped   bool
	stop      chan struct{}
	done      chan struct{}
}

func freeTCPPort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// startTorProc writes the torrc and starts tor in the background.
func startTorProc(exe, dir string, bridges []string, pt string, logf func(string, ...any)) (*torProc, error) {
	p := &torProc{exe: exe, dir: dir, pt: pt, logf: logf, stop: make(chan struct{}), done: make(chan struct{}), kick: make(chan struct{}, 1)}
	p.bridges = tunnel.ExpandBridges(bridges)
	if err := os.MkdirAll(filepath.Join(dir, "data"), 0o700); err != nil {
		return nil, err
	}
	var err error
	if p.socksPort, err = freeTCPPort(); err != nil {
		return nil, err
	}
	if p.ctlPort, err = freeTCPPort(); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "torrc"), []byte(p.torrc()), 0o600); err != nil {
		return nil, err
	}
	_ = os.Remove(p.cookiePath())
	go p.loop()
	return p, nil
}

func (p *torProc) cookiePath() string { return filepath.Join(p.dir, "control_auth_cookie") }

func (p *torProc) torrc() string {
	var b strings.Builder
	fmt.Fprintf(&b, "DataDirectory %s\n", filepath.Join(p.dir, "data"))
	fmt.Fprintf(&b, "SOCKSPort 127.0.0.1:%d\n", p.socksPort)
	fmt.Fprintf(&b, "ControlPort 127.0.0.1:%d\n", p.ctlPort)
	fmt.Fprintf(&b, "CookieAuthentication 1\nCookieAuthFile %s\n", p.cookiePath())
	b.WriteString("ClientOnly 1\nAvoidDiskWrites 1\nSafeLogging 1\nLog notice stderr\n")
	b.WriteString("AutomapHostsOnResolve 1\nVirtualAddrNetworkIPv4 10.192.0.0/10\n")
	// GeoIP tables the app copies next to the Tor folders (exit country)
	for _, g := range [][2]string{{"GeoIPFile", "geoip"}, {"GeoIPv6File", "geoip6"}} {
		if f := filepath.Join(filepath.Dir(p.dir), g[1]); fileExists(f) {
			fmt.Fprintf(&b, "%s %s\n", g[0], f)
		}
	}
	if len(p.bridges) > 0 {
		b.WriteString("UseBridges 1\n")
		if p.pt != "" {
			fmt.Fprintf(&b, "ClientTransportPlugin obfs4,meek_lite,webtunnel,snowflake exec %s\n", p.pt)
		}
		for _, br := range p.bridges {
			fmt.Fprintf(&b, "Bridge %s\n", br)
		}
	}
	return b.String()
}

// Socks is the SOCKS address tor listens on.
func (p *torProc) Socks() string { return "127.0.0.1:" + strconv.Itoa(p.socksPort) }

func (p *torProc) loop() {
	defer close(p.done)
	backoff := 2 * time.Second
	for {
		started := time.Now()
		err := p.runOnce()
		p.mu.Lock()
		if err != nil && !p.errRun {
			p.lastErr = p.exitReason(err)
		}
		p.bootstrap = 0
		stopped := p.stopped
		p.mu.Unlock()
		if stopped {
			return
		}
		p.logf("tor ended (%v), restarting", err)
		if time.Since(started) > time.Minute {
			backoff = 2 * time.Second
		}
		select {
		case <-p.stop:
			return
		case <-p.kick: // "start now": no more waiting
			backoff = 2 * time.Second
			continue
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

// exitReason says why tor ended: the error or exit code, with its last line
// (on a phone a program often dies silently: killed by a signal, no [err]).
// Call with p.mu held.
func (p *torProc) exitReason(err error) string {
	var ee *exec.ExitError
	msg := err.Error()
	if errors.As(err, &ee) {
		msg = "tor ended: " + ee.String()
	}
	if p.lastLine != "" {
		msg += " (last line: " + p.lastLine + ")"
	}
	return msg
}

// Kick ends the wait before the next start of tor (a tor that is running is left alone).
func (p *torProc) Kick() {
	select {
	case p.kick <- struct{}{}:
	default:
	}
}

func (p *torProc) runOnce() error {
	cmd := exec.Command(p.exe, "-f", filepath.Join(p.dir, "torrc"))
	cmd.Dir = p.dir
	pr, pw := io.Pipe() // Wait then returns only after all of stderr is copied: the last line is the reason tor died
	cmd.Stderr = pw
	cmd.Stdout = nil
	if err := cmd.Start(); err != nil {
		pw.Close()
		return err
	}
	p.mu.Lock()
	p.proc = cmd.Process
	p.errRun = false
	stopped := p.stopped
	p.mu.Unlock()
	if stopped {
		_ = cmd.Process.Kill()
	}
	logged := make(chan struct{})
	go func() { p.readLog(pr); close(logged) }()
	go p.watchBootstrap(cmd.Process.Pid)
	err := cmd.Wait()
	pw.Close()
	select {
	case <-logged:
	case <-time.After(time.Second):
	}
	return err
}

func (p *torProc) readLog(r interface{ Read([]byte) (int, error) }) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		l := sc.Text()
		p.mu.Lock()
		if t := trimTorLine(l); t != "" {
			p.lastLine = t
		}
		if strings.Contains(l, "[err]") {
			p.lastErr, p.errRun = trimTorLine(l), true
		}
		p.mu.Unlock()
		if tl := trimTorLine(l); strings.Contains(l, "[warn]") || strings.Contains(l, "[err]") || strings.Contains(tl, "Bootstrapped") {
			p.logf("tor: %s", tl) // not every notice: the control connection is opened each second
		}
	}
}

func trimTorLine(l string) string {
	if i := strings.Index(l, "] "); i >= 0 {
		return l[i+2:]
	}
	return l
}

// watchBootstrap polls the progress over the control port while this tor lives.
func (p *torProc) watchBootstrap(pid int) {
	for {
		select {
		case <-p.stop:
			return
		case <-time.After(time.Second):
		}
		p.mu.Lock()
		cur := p.proc
		p.mu.Unlock()
		if cur == nil || cur.Pid != pid {
			return
		}
		lines, err := p.control("GETINFO status/bootstrap-phase")
		if err != nil {
			continue
		}
		for _, l := range lines {
			if i := strings.Index(l, "PROGRESS="); i >= 0 {
				n, _ := strconv.Atoi(strings.Fields(l[i+9:])[0])
				p.mu.Lock()
				p.bootstrap = n
				if n == 100 {
					p.lastErr = ""
				}
				p.mu.Unlock()
			}
		}
	}
}

// controlData is control for replies with data blocks (circuit-status:
// "250+key=", lines, "."), which control does not read.
func (p *torProc) controlData(cmds ...string) ([]string, error) {
	cookie, err := os.ReadFile(p.cookiePath())
	if err != nil || len(cookie) == 0 {
		return nil, errors.New("no cookie yet")
	}
	c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(p.ctlPort), 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return tunnel.ControlExchange(c, cookie, cmds)
}

// control authenticates with the cookie and sends the commands.
func (p *torProc) control(cmds ...string) ([]string, error) {
	cookie, err := os.ReadFile(p.cookiePath())
	if err != nil || len(cookie) == 0 {
		return nil, errors.New("no cookie yet")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", "127.0.0.1:"+strconv.Itoa(p.ctlPort))
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(c)
	var out []string
	send := func(cmd string) error {
		if _, err := fmt.Fprintf(c, "%s\r\n", cmd); err != nil {
			return err
		}
		for {
			l, err := r.ReadString('\n')
			if err != nil {
				return err
			}
			l = strings.TrimRight(l, "\r\n")
			if len(l) < 4 {
				continue
			}
			if l[0] != '2' {
				return errors.New(l)
			}
			out = append(out, l)
			if l[3] == ' ' {
				return nil
			}
		}
	}
	if err := send("AUTHENTICATE " + hex.EncodeToString(cookie)); err != nil {
		return nil, err
	}
	out = nil
	for _, cmd := range cmds {
		if err := send(cmd); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// Bootstrap is the progress of the current tor, 0..100.
func (p *torProc) Bootstrap() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.bootstrap
}

// Err is the last warning or error of tor ("" when it runs well).
func (p *torProc) Err() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastErr
}

// NewIdentity asks tor for fresh circuits.
func (p *torProc) NewIdentity() error {
	_, err := p.control("SIGNAL NEWNYM")
	if err == nil {
		p.mu.Lock()
		p.newnymAt, p.circAt = time.Now().UTC(), time.Time{}
		p.mu.Unlock()
	}
	return err
}

// Circuit is the path new connections take (exit country, relay, address,
// hops), nil until tor is through or has none; asked at most every 4 s.
func (p *torProc) Circuit() *tunnel.TorCircuit {
	p.mu.Lock()
	if p.bootstrap < 100 {
		p.mu.Unlock()
		return nil
	}
	if time.Since(p.circAt) < 4*time.Second {
		c := p.circ
		p.mu.Unlock()
		return c
	}
	since := p.newnymAt
	p.mu.Unlock()
	c, _ := tunnel.QueryCircuit(p.controlData, len(p.bridges) > 0, since)
	p.mu.Lock()
	p.circ, p.circAt = c, time.Now()
	p.mu.Unlock()
	return c
}

// Close stops tor.
func (p *torProc) Close() {
	p.mu.Lock()
	p.stopped = true
	proc := p.proc
	p.mu.Unlock()
	close(p.stop)
	if proc != nil {
		_ = proc.Kill()
	}
	select {
	case <-p.done:
	case <-time.After(3 * time.Second):
	}
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular()
}
