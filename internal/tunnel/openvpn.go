package tunnel

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
)

// OpenVPNSpec describes an OpenVPN tunnel.
type OpenVPNSpec struct {
	Name     string
	Iface    string
	Config   string // .ovpn path, checked by ovpnconf
	AuthFile string // username/password file for auth-user-pass, or ""
	Mark     uint32 // mark for the encrypted packets (bypass, or a hop's route)
	PIDDir   string // where the pid file of the running openvpn goes
}

// OpenVPN runs the openvpn binary for one tunnel and keeps it running.
//
// shuntd does what openvpn's scripts would do elsewhere: openvpn only
// creates the TUN interface and sets its address (--route-noexec, script
// level 1, no scripts). Routes go into the tunnel's own table, DNS servers
// pushed by the server go to the DNS proxy.
type OpenVPN struct {
	spec    OpenVPNSpec
	log     *slog.Logger
	changed func() // connect/disconnect/DNS change; must not block

	mu        sync.Mutex
	connected bool
	since     time.Time
	endpoint  string
	dns       []netip.Addr
	pending   []netip.Addr // from the last PUSH_REPLY, applied on connect
	lastErr   string
	proc      *os.Process

	stop chan struct{}
	done chan struct{}
}

// openvpnBinary is a variable for tests.
var openvpnBinary = "openvpn"

// StartOpenVPN starts openvpn in the background. changed is called (from
// another goroutine) whenever the connection state or DNS servers change.
func StartOpenVPN(s OpenVPNSpec, log *slog.Logger, changed func()) (*OpenVPN, error) {
	bin, err := exec.LookPath(openvpnBinary)
	if err != nil {
		return nil, errors.New("openvpn is not installed (sudo apt install openvpn)")
	}
	if l, err := netlink.LinkByName(s.Iface); err == nil {
		_ = netlink.LinkDel(l)
	}
	o := &OpenVPN{spec: s, log: log, changed: changed, stop: make(chan struct{}), done: make(chan struct{})}
	o.killLeftover()
	go o.loop(bin)
	return o, nil
}

func (o *OpenVPN) pidFile() string {
	if o.spec.PIDDir == "" {
		return ""
	}
	return filepath.Join(o.spec.PIDDir, "openvpn-"+o.spec.Name+".pid")
}

// killLeftover stops an openvpn of this tunnel that survived a crash of
// shuntd (it would hold the interface name and the server session).
func (o *OpenVPN) killLeftover() {
	pf := o.pidFile()
	if pf == "" {
		return
	}
	b, err := os.ReadFile(pf)
	if err != nil {
		return
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	if pid <= 1 {
		return
	}
	cmd, _ := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if strings.Contains(string(cmd), "openvpn") && strings.Contains(string(cmd), "\x00"+o.spec.Iface+"\x00") {
		_ = syscall.Kill(pid, syscall.SIGKILL)
		o.log.Warn("killed leftover openvpn", "tunnel", o.spec.Name, "pid", pid)
	}
	_ = os.Remove(pf)
}

func (o *OpenVPN) args() []string {
	a := []string{
		"--config", o.spec.Config,
		"--cd", filepath.Dir(o.spec.Config),
		"--dev", o.spec.Iface, "--dev-type", "tun",
		"--mark", strconv.FormatUint(uint64(o.spec.Mark), 10),
		"--route-noexec", "--persist-tun",
		// openvpn drops tunnel packets to its own server address, against
		// routing loops; marks rule those out, and apps may well talk to
		// the server's address (provider sites, a self-hosted server).
		"--allow-recursive-routing",
		"--script-security", "1",
		"--resolv-retry", "infinite",
		"--pull-filter", "ignore", "redirect-gateway",
		"--pull-filter", "ignore", "block-outside-dns",
		"--verb", "3", "--suppress-timestamps",
	}
	if o.spec.AuthFile != "" {
		a = append(a, "--auth-user-pass", o.spec.AuthFile, "--auth-retry", "none")
	}
	return a
}

func (o *OpenVPN) loop(bin string) {
	defer close(o.done)
	backoff := 5 * time.Second
	for {
		started := time.Now()
		err := o.runOnce(bin)
		o.setDown()
		select {
		case <-o.stop:
			return
		default:
		}
		if time.Since(started) > 2*time.Minute {
			backoff = 5 * time.Second
		}
		o.mu.Lock()
		if o.lastErr == "" && err != nil {
			o.lastErr = err.Error()
		}
		msg := o.lastErr
		o.mu.Unlock()
		o.log.Warn("openvpn stopped, restarting", "tunnel", o.spec.Name, "in", backoff, "err", msg)
		select {
		case <-o.stop:
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, time.Minute)
	}
}

// runOnce runs openvpn until it exits. The OS thread stays locked so
// Pdeathsig (sent when the thread that started the child exits) only fires
// when shuntd itself dies.
func (o *OpenVPN) runOnce(bin string) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	cmd := exec.Command(bin, o.args()...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return err
	}
	o.mu.Lock()
	o.proc = cmd.Process
	o.mu.Unlock()
	if pf := o.pidFile(); pf != "" {
		_ = os.WriteFile(pf, []byte(strconv.Itoa(cmd.Process.Pid)), 0o600)
	}
	select {
	case <-o.stop: // Down() raced with the start
		_ = cmd.Process.Signal(syscall.SIGTERM)
	default:
	}
	o.readLog(out)
	err = cmd.Wait()
	if pf := o.pidFile(); pf != "" {
		_ = os.Remove(pf)
	}
	return err
}

func (o *OpenVPN) readLog(r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 16<<10), 256<<10)
	for sc.Scan() {
		o.handleLine(sc.Text())
	}
}

// handleLine follows openvpn's log (verb 3). It is the only interface we
// need: no management socket, no scripts.
func (o *OpenVPN) handleLine(l string) {
	notify := false
	o.mu.Lock()
	switch {
	case strings.Contains(l, "Initialization Sequence Completed"):
		o.connected, o.since, o.lastErr = true, time.Now(), ""
		o.dns = o.pending
		notify = true
		o.log.Info("openvpn connected", "tunnel", o.spec.Name, "endpoint", o.endpoint, "dns", o.dns)
	case strings.Contains(l, "PUSH: Received control message:"):
		o.pending = pushedDNS(l)
	case strings.Contains(l, "Peer Connection Initiated with"):
		if i := strings.LastIndex(l, "]"); i >= 0 {
			o.endpoint = strings.TrimSpace(l[i+1:])
		}
	case strings.Contains(l, "AUTH_FAILED"):
		o.lastErr = "authentication failed: wrong username or password?"
		o.log.Warn("openvpn: authentication failed", "tunnel", o.spec.Name)
	case strings.Contains(l, "SIGUSR1[") || strings.Contains(l, "SIGHUP[") || strings.Contains(l, "Restart pause") || strings.Contains(l, "Inactivity timeout"):
		if o.connected {
			o.connected = false
			notify = true
		}
		o.log.Warn("openvpn: "+l, "tunnel", o.spec.Name)
	case strings.Contains(l, "ERROR") || strings.Contains(l, "Options error") || strings.Contains(l, "Cannot ") || strings.Contains(l, "Exiting due to fatal error"):
		if !strings.Contains(l, "Exiting due to fatal error") || o.lastErr == "" {
			o.lastErr = l
		}
		o.log.Warn("openvpn: "+l, "tunnel", o.spec.Name)
	default:
		o.log.Debug("openvpn: "+l, "tunnel", o.spec.Name)
	}
	o.mu.Unlock()
	if notify && o.changed != nil {
		o.changed()
	}
}

// pushedDNS extracts DNS servers from a PUSH_REPLY log line: classic
// "dhcp-option DNS x" / "DNS6 x" and OpenVPN 2.6 "dns server N address x".
func pushedDNS(l string) []netip.Addr {
	if i := strings.Index(l, "'"); i >= 0 {
		l = strings.Trim(l[i:], "'")
	}
	var out []netip.Addr
	for _, opt := range strings.Split(l, ",") {
		f := strings.Fields(opt)
		var addrs []string
		switch {
		case len(f) == 3 && f[0] == "dhcp-option" && (f[1] == "DNS" || f[1] == "DNS6"):
			addrs = f[2:3]
		case len(f) >= 5 && f[0] == "dns" && f[1] == "server" && f[3] == "address":
			addrs = f[4:]
		}
		for _, s := range addrs {
			if ap, err := netip.ParseAddrPort(s); err == nil {
				s = ap.Addr().String()
			}
			if a, err := netip.ParseAddr(s); err == nil && !a.IsUnspecified() {
				out = append(out, a.Unmap())
			}
		}
	}
	return out
}

func (o *OpenVPN) setDown() {
	o.mu.Lock()
	was := o.connected
	o.connected, o.proc = false, nil
	o.mu.Unlock()
	if was && o.changed != nil {
		o.changed()
	}
}

// DriverName implements Device.
func (o *OpenVPN) DriverName() string { return "openvpn" }

// Down stops openvpn and removes the interface.
func (o *OpenVPN) Down() {
	select {
	case <-o.stop:
	default:
		close(o.stop)
	}
	o.mu.Lock()
	p := o.proc
	o.mu.Unlock()
	if p != nil {
		_ = p.Signal(syscall.SIGTERM)
	}
	select {
	case <-o.done:
	case <-time.After(5 * time.Second):
		o.mu.Lock()
		if o.proc != nil {
			_ = o.proc.Kill()
		}
		o.mu.Unlock()
		<-o.done
	}
	if l, err := netlink.LinkByName(o.spec.Iface); err == nil {
		_ = netlink.LinkDel(l)
	}
}

// Alive implements Device: openvpn restarts itself (see loop), so the
// daemon never needs to.
func (o *OpenVPN) Alive() bool { return true }

// Connected reports whether the tunnel is up and the server reachable.
func (o *OpenVPN) Connected() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.connected
}

// DNS returns the DNS servers the server pushed (empty while disconnected).
func (o *OpenVPN) DNS() []netip.Addr {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.connected {
		return nil
	}
	return append([]netip.Addr(nil), o.dns...)
}

// Err implements Device.
func (o *OpenVPN) Err() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.connected {
		return ""
	}
	return o.lastErr
}

// Status implements Device. There is one "peer", the server; LastHandshake
// is the time the connection was established (zero while disconnected).
func (o *OpenVPN) Status() ([]PeerStatus, error) {
	o.mu.Lock()
	ps := PeerStatus{Endpoint: o.endpoint}
	if o.connected {
		ps.LastHandshake = o.since
	}
	o.mu.Unlock()
	if l, err := netlink.LinkByName(o.spec.Iface); err == nil {
		if st := l.Attrs().Statistics; st != nil {
			ps.RxBytes, ps.TxBytes = int64(st.RxBytes), int64(st.TxBytes)
		}
	}
	return []PeerStatus{ps}, nil
}

// Reresolve implements Device; openvpn re-resolves remotes itself.
func (o *OpenVPN) Reresolve(time.Time) ([]string, error) { return nil, nil }

func (o *OpenVPN) String() string { return fmt.Sprintf("openvpn(%s)", o.spec.Name) }
