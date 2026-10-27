package tunnel

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Tor runs a tor process for one tunnel and keeps it running. Tor is a
// plain child of shuntd: it sits in the daemon's cgroup (its own traffic is
// not classified) and in the unit's sandbox (no capabilities beyond
// shuntd's). Apps reach it through shuntd's SOCKS exit and transparent
// proxy, never directly.
type Tor struct {
	spec TorSpec
	log  *slog.Logger
	// changed: bootstrap or state changed; must not block.
	changed func()

	dir     string // run dir with the sockets
	dnsPort int

	mu      sync.Mutex
	running bool
	lastErr string
	proc    *os.Process

	stop chan struct{}
	done chan struct{}
}

// torBinary is a variable for tests.
var torBinary = "tor"

// StartTor starts tor in the background.
func StartTor(s TorSpec, log *slog.Logger, changed func()) (*Tor, error) {
	bin, err := exec.LookPath(torBinary)
	if err != nil {
		return nil, errors.New("tor is not installed (sudo apt install tor)")
	}
	t := &Tor{spec: s, log: log, changed: changed,
		dir: filepath.Join(s.RunDir, "tor-"+s.Name), stop: make(chan struct{}), done: make(chan struct{})}
	if t.dnsPort, err = freeUDPPort(); err != nil {
		return nil, err
	}
	s.Bridges = ExpandBridges(s.Bridges)
	t.spec.Bridges = s.Bridges
	plugins, err := torPlugins(s.Bridges)
	if err != nil {
		return nil, err
	}
	if err := t.prepareDirs(); err != nil {
		return nil, err
	}
	rc, err := t.torrc(plugins)
	if err != nil {
		return nil, err
	}
	rcPath := filepath.Join(t.dir, "torrc")
	if err := os.WriteFile(rcPath, []byte(rc), 0o600); err != nil {
		return nil, err
	}
	go t.loop(bin, rcPath)
	return t, nil
}

func (t *Tor) prepareDirs() error {
	for _, d := range []string{t.spec.DataDir, t.dir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
		if err := os.Chmod(d, 0o700); err != nil {
			return err
		}
	}
	// a stale socket from a crash would make tor fail to bind
	_ = os.Remove(t.SocksPath())
	_ = os.Remove(t.controlPath())
	return nil
}

func freeUDPPort() (int, error) {
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port, nil
}

// SocksPath is tor's SOCKS socket (only root and tor can open it).
func (t *Tor) SocksPath() string { return filepath.Join(t.dir, "socks") }

func (t *Tor) controlPath() string { return filepath.Join(t.dir, "control") }

// DNSAddr is tor's DNSPort on loopback.
func (t *Tor) DNSAddr() string { return "127.0.0.1:" + strconv.Itoa(t.dnsPort) }

// ptDirs are searched for the pluggable transports before PATH: the
// packages and install.sh put lyrebird next to the daemon's helpers.
var ptDirs = []string{"/usr/libexec/shunt", "/usr/local/libexec/shunt"}

func findPT(name string) string {
	for _, d := range ptDirs {
		p := filepath.Join(d, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			return p
		}
	}
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	return ""
}

// torPlugins returns the ClientTransportPlugin lines the bridges need.
// lyrebird speaks obfs4, meek_lite, webtunnel and snowflake; without it,
// obfs4proxy (obfs4 only) and snowflake-client from the distribution do.
func torPlugins(bridges []string) ([]string, error) {
	need := map[string]bool{}
	for _, b := range bridges {
		if f := strings.Fields(b); len(f) > 0 && !strings.ContainsAny(f[0], ".:[") { // a transport name, not an address
			need[f[0]] = true
		}
	}
	if len(need) == 0 {
		return nil, nil
	}
	var names []string
	for n := range need {
		names = append(names, n)
	}
	sort.Strings(names)
	if p := findPT("lyrebird"); p != "" {
		return []string{"ClientTransportPlugin " + strings.Join(names, ",") + " exec " + p}, nil
	}
	var out, rest []string
	for _, n := range names {
		if n == "snowflake" {
			p := findPT("snowflake-client")
			if p == "" {
				return nil, errors.New("bridges use snowflake, but neither lyrebird nor snowflake-client is installed")
			}
			out = append(out, "ClientTransportPlugin snowflake exec "+p)
			continue
		}
		rest = append(rest, n)
	}
	if len(rest) > 0 {
		p := findPT("obfs4proxy")
		if p == "" || strings.Join(rest, ",") != "obfs4" {
			return nil, errors.New("bridges (" + strings.Join(rest, ", ") + ") need lyrebird, which is not installed")
		}
		out = append(out, "ClientTransportPlugin obfs4 exec "+p)
	}
	return out, nil
}

func (t *Tor) torrc(plugins []string) (string, error) {
	for _, b := range t.spec.Bridges {
		if strings.ContainsAny(b, "\r\n") {
			return "", errors.New("bridge line with a line break")
		}
	}
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	w("DataDirectory %s", t.spec.DataDir)
	w("Log notice stdout")
	w("SafeLogging 1")
	// no "User": tor stays in shuntd's own (capability-bound) unit, as root
	// without any capability; it could not switch users there anyway
	flags := ""
	switch t.spec.Isolate {
	case "destination":
		flags = " IsolateDestAddr IsolateDestPort"
	case "none":
		flags = " NoIsolateSOCKSAuth NoIsolateClientAuth"
	}
	// app (default): tor's default IsolateSOCKSAuth, the user name is the app
	w("SocksPort unix:%s%s", t.SocksPath(), flags)
	w("DNSPort 127.0.0.1:%d", t.dnsPort)
	w("AutomapHostsOnResolve 1")
	w("VirtualAddrNetworkIPv4 10.192.0.0/10")
	w("ControlSocket %s", t.controlPath())
	w("CookieAuthentication 1")
	w("CookieAuthFile %s", filepath.Join(t.spec.DataDir, "control_auth_cookie"))
	w("ClientUseIPv6 1")
	if len(t.spec.Bridges) > 0 {
		w("UseBridges 1")
		for _, p := range plugins {
			w("%s", p)
		}
		for _, br := range t.spec.Bridges {
			w("Bridge %s", strings.TrimPrefix(strings.TrimSpace(br), "Bridge "))
		}
	}
	return b.String(), nil
}

func (t *Tor) loop(bin, rc string) {
	defer close(t.done)
	backoff := 5 * time.Second
	for {
		started := time.Now()
		err := t.runOnce(bin, rc)
		t.mu.Lock()
		t.running = false
		if err != nil && t.lastErr == "" {
			t.lastErr = err.Error()
		}
		t.mu.Unlock()
		t.notify()
		select {
		case <-t.stop:
			return
		default:
		}
		if time.Since(started) > 2*time.Minute {
			backoff = 5 * time.Second
		}
		t.log.Warn("tor stopped, restarting", "tunnel", t.spec.Name, "in", backoff, "err", err)
		select {
		case <-t.stop:
			return
		case <-time.After(backoff):
		}
		if backoff < 2*time.Minute {
			backoff *= 2
		}
		_ = os.Remove(t.SocksPath())
		_ = os.Remove(t.controlPath())
	}
}

func (t *Tor) notify() {
	if t.changed != nil {
		t.changed()
	}
}

func (t *Tor) runOnce(bin, rc string) error {
	cmd := exec.Command(bin, "-f", rc)
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return err
	}
	t.mu.Lock()
	t.proc, t.running, t.lastErr = cmd.Process, true, ""
	t.mu.Unlock()
	t.notify()
	go t.readLog(out)
	return cmd.Wait()
}

func (t *Tor) readLog(r io.Reader) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		l := sc.Text()
		switch {
		case strings.Contains(l, "[err]"):
			t.mu.Lock()
			t.lastErr = trimTorLog(l)
			t.mu.Unlock()
			t.log.Warn("tor", "tunnel", t.spec.Name, "msg", trimTorLog(l))
		case strings.Contains(l, "[warn]"):
			t.log.Warn("tor", "tunnel", t.spec.Name, "msg", trimTorLog(l))
		case strings.Contains(l, "Bootstrapped 100%"):
			t.log.Info("tor connected", "tunnel", t.spec.Name)
			t.notify()
		default:
			t.log.Debug("tor", "tunnel", t.spec.Name, "msg", trimTorLog(l))
		}
	}
}

// trimTorLog drops tor's timestamp and level prefix.
func trimTorLog(l string) string {
	if i := strings.Index(l, "] "); i >= 0 {
		return l[i+2:]
	}
	return l
}

// control runs commands on tor's control socket and returns the reply lines.
func (t *Tor) control(cmds ...string) ([]string, error) {
	cookie, err := os.ReadFile(filepath.Join(t.spec.DataDir, "control_auth_cookie"))
	if err != nil {
		return nil, err
	}
	c, err := net.DialTimeout("unix", t.controlPath(), 3*time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	rd := bufio.NewReader(c)
	var out []string
	send := func(cmd string) error {
		if _, err := fmt.Fprintf(c, "%s\r\n", cmd); err != nil {
			return err
		}
		for {
			l, err := rd.ReadString('\n')
			if err != nil {
				return err
			}
			l = strings.TrimRight(l, "\r\n")
			if len(l) < 4 {
				continue
			}
			out = append(out, l[4:])
			if l[3] == ' ' { // last line of the reply
				if l[0] != '2' {
					return errors.New(l[4:])
				}
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
			return out, err
		}
	}
	return out, nil
}

// Bootstrap returns tor's progress, 0 to 100.
func (t *Tor) Bootstrap() int {
	t.mu.Lock()
	run := t.running
	t.mu.Unlock()
	if !run {
		return 0
	}
	lines, err := t.control("GETINFO status/bootstrap-phase")
	if err != nil {
		return 0
	}
	for _, l := range lines {
		if i := strings.Index(l, "PROGRESS="); i >= 0 {
			f := strings.Fields(l[i+len("PROGRESS="):])
			if len(f) > 0 {
				n, _ := strconv.Atoi(f[0])
				return n
			}
		}
	}
	return 0
}

// NewIdentity asks tor for fresh circuits (SIGNAL NEWNYM).
func (t *Tor) NewIdentity() error {
	_, err := t.control("SIGNAL NEWNYM")
	return err
}

// DriverName implements Device.
func (t *Tor) DriverName() string { return "tor" }

// Alive implements Device: the process runs.
func (t *Tor) Alive() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.running
}

// Status implements Device (Tor has no peers).
func (t *Tor) Status() ([]PeerStatus, error) { return nil, nil }

// Reresolve implements Device (nothing to re-resolve).
func (t *Tor) Reresolve(time.Time) ([]string, error) { return nil, nil }

// Err implements Device.
func (t *Tor) Err() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.lastErr
}

// Down stops tor.
func (t *Tor) Down() {
	close(t.stop)
	t.mu.Lock()
	p := t.proc
	t.mu.Unlock()
	if p != nil {
		_ = p.Signal(syscall.SIGTERM)
	}
	select {
	case <-t.done:
	case <-time.After(6 * time.Second):
		if p != nil {
			_ = p.Kill()
		}
		<-t.done
	}
	_ = os.Remove(t.SocksPath())
	_ = os.Remove(t.controlPath())
}

var _ TorStatus = (*Tor)(nil)
var _ Device = (*Tor)(nil)
