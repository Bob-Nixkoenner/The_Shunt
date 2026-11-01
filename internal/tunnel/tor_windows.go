package tunnel

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Tor runs tor.exe for one tunnel and keeps it running (Windows). tor.exe has
// no Unix sockets, so SocksPort and ControlPort are loopback TCP ports chosen
// at start; apps never see them, shuntd-win's engine dials the SOCKS port. A
// job object ends tor (and its transports) with the service, however it ends.
type Tor struct {
	spec    TorSpec
	log     *slog.Logger
	changed func()

	socksPort, controlPort int
	cookie                 string

	mu      sync.Mutex
	running bool
	lastErr string
	proc    *os.Process

	job  windows.Handle
	stop chan struct{}
	done chan struct{}
}

// ptDirs: the transports sit in tor\pt next to the program, see FindTor.
var ptDirs []string

// TorDir is the folder with tor.exe (and pt\lyrebird.exe) next to the
// program; it can be set for tests.
var TorDir = func() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Join(filepath.Dir(exe), "tor")
}

// FindTor returns tor.exe from the install folder (Setup puts it there), else
// from PATH. "" if neither exists.
func FindTor() string {
	if d := TorDir(); d != "" {
		p := filepath.Join(d, "tor.exe")
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	if p, err := exec.LookPath("tor.exe"); err == nil {
		return p
	}
	return ""
}

// StartTor starts tor in the background.
func StartTor(s TorSpec, log *slog.Logger, changed func()) (*Tor, error) {
	bin := FindTor()
	if bin == "" {
		return nil, errors.New("tor.exe is not installed (reinstall The Shunt with Tor, or put tor.exe in the tor folder next to shuntd-win.exe)")
	}
	if d := TorDir(); d != "" {
		ptDirs = []string{filepath.Join(d, "pt"), d}
	}
	t := &Tor{spec: s, log: log, changed: changed, stop: make(chan struct{}), done: make(chan struct{})}
	var err error
	if t.socksPort, err = freeTCPPort(); err != nil {
		return nil, err
	}
	if t.controlPort, err = freeTCPPort(); err != nil {
		return nil, err
	}
	t.spec.Bridges = ExpandBridges(s.Bridges)
	plugins, err := torPlugins(t.spec.Bridges)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(s.DataDir, 0o700); err != nil {
		return nil, err
	}
	_ = os.Remove(t.cookiePath())
	rc, err := t.torrc(plugins)
	if err != nil {
		return nil, err
	}
	rcPath := filepath.Join(s.DataDir, "torrc")
	if err := os.WriteFile(rcPath, []byte(rc), 0o600); err != nil {
		return nil, err
	}
	if t.job, err = killOnCloseJob(); err != nil {
		return nil, err
	}
	go t.loop(bin, rcPath)
	return t, nil
}

func killOnCloseJob() (windows.Handle, error) {
	h, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(h, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		windows.CloseHandle(h)
		return 0, err
	}
	return h, nil
}

func freeTCPPort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// SocksAddr is tor's SOCKS5 port on loopback.
func (t *Tor) SocksAddr() string { return "127.0.0.1:" + strconv.Itoa(t.socksPort) }

// SocksPath is empty: tor.exe listens on TCP here (see SocksAddr).
func (t *Tor) SocksPath() string { return "" }

// DNSAddr is empty: names are resolved through the SOCKS port.
func (t *Tor) DNSAddr() string { return "" }

func (t *Tor) cookiePath() string { return filepath.Join(t.spec.DataDir, "control_auth_cookie") }

// short returns the 8.3 name of an existing path: tor splits the transport
// command on spaces, "C:\Program Files\..." would break.
func short(p string) string {
	u, err := windows.UTF16PtrFromString(p)
	if err != nil {
		return p
	}
	buf := make([]uint16, 520)
	n, err := windows.GetShortPathName(u, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 || int(n) > len(buf) {
		return p
	}
	return windows.UTF16ToString(buf[:n])
}

func (t *Tor) torrc(plugins []string) (string, error) {
	for _, b := range t.spec.Bridges {
		if strings.ContainsAny(b, "\r\n") {
			return "", errors.New("bridge line with a line break")
		}
	}
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	// the 8.3 names have neither spaces nor quotes: backslashes are fine in the
	// torrc and keep tor from calling the "C:/..." path relative
	fwd := func(p string) string { return p }
	w("DataDirectory %s", fwd(short(t.spec.DataDir)))
	w("Log notice stdout")
	w("SafeLogging 1")
	flags := ""
	switch t.spec.Isolate {
	case "destination":
		flags = " IsolateDestAddr IsolateDestPort"
	case "none":
		flags = " NoIsolateSOCKSAuth NoIsolateClientAuth"
	}
	w("SocksPort 127.0.0.1:%d%s", t.socksPort, flags)
	w("AutomapHostsOnResolve 1")
	w("VirtualAddrNetworkIPv4 10.192.0.0/10")
	w("ControlPort 127.0.0.1:%d", t.controlPort)
	w("CookieAuthentication 1")
	w("CookieAuthFile %s", fwd(short(t.spec.DataDir))+`\control_auth_cookie`)
	w("ClientUseIPv6 1")
	// the GeoIP tables ship next to tor.exe; tor's default path is relative
	// (C:\Windows\system32 for the service) and only earns a warning
	if d := TorDir(); d != "" {
		for _, g := range [][2]string{{"GeoIPFile", "geoip"}, {"GeoIPv6File", "geoip6"}} {
			if st, err := os.Stat(filepath.Join(d, g[1])); err == nil && !st.IsDir() {
				w("%s %s", g[0], fwd(short(filepath.Join(d, g[1]))))
			}
		}
	}
	if len(t.spec.Bridges) > 0 {
		w("UseBridges 1")
		for _, p := range plugins {
			// "exec <path>": use the short name so the path has no spaces
			if i := strings.Index(p, " exec "); i >= 0 {
				p = p[:i+6] + fwd(short(p[i+6:]))
			}
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
	}
}

func (t *Tor) notify() {
	if t.changed != nil {
		t.changed()
	}
}

func (t *Tor) runOnce(bin, rc string) error {
	cmd := exec.Command(bin, "-f", rc)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return err
	}
	// into the job: tor and the transports it starts end with the service
	if h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid)); err == nil {
		_ = windows.AssignProcessToJobObject(t.job, h)
		windows.CloseHandle(h)
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

// control runs commands on tor's control port and returns the reply lines.
func (t *Tor) control(cmds ...string) ([]string, error) {
	cookie, err := os.ReadFile(t.cookiePath())
	if err != nil {
		return nil, err
	}
	c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(t.controlPort), 3*time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return controlExchange(c, cookie, cmds)
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
	if err == nil {
		markNewnym(t)
	}
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
		_ = p.Kill()
	}
	select {
	case <-t.done:
	case <-time.After(6 * time.Second):
	}
	windows.CloseHandle(t.job) // ends the transports too
}

var _ Device = (*Tor)(nil)

// TorApps are the programs a Tor tunnel runs (tor.exe and the transports):
// the kill switch lets them send like the service itself.
func TorApps() []string {
	var out []string
	if p := FindTor(); p != "" {
		out = append(out, p)
	}
	if d := TorDir(); d != "" {
		for _, n := range []string{"lyrebird.exe", "snowflake-client.exe", "obfs4proxy.exe"} {
			for _, p := range []string{filepath.Join(d, "pt", n), filepath.Join(d, n)} {
				if st, err := os.Stat(p); err == nil && !st.IsDir() {
					out = append(out, p)
				}
			}
		}
	}
	return out
}
