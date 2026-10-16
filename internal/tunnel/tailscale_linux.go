package tunnel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
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
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// nsTun is the name of tailscaled's TUN device inside the namespace.
const nsTun = "ts0"

// Tailscale runs tailscaled for one tunnel and keeps it running.
type Tailscale struct {
	spec    TailscaleSpec
	log     *slog.Logger
	changed func()
	// ns is the namespace tailscaled runs in. It has no name and no mount
	// point (that would need CAP_SYS_ADMIN for mount and a writable /run):
	// it lives as long as this handle or a process in it, so a crash of
	// shuntd cleans up after itself.
	ns     netns.NsHandle
	peerIf string
	sock   string

	mu        sync.Mutex
	connected bool
	since     time.Time
	endpoint  string
	lastErr   string
	proc      *os.Process

	stop chan struct{}
	done chan struct{}
}

// binaries are variables for tests.
var tailscaledBinary, tailscaleBinary = "tailscaled", "tailscale"

func lookPath(name string) (string, error) {
	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}
	for _, d := range []string{"/usr/sbin", "/usr/local/bin", "/usr/local/sbin", "/usr/bin"} {
		if p := filepath.Join(d, name); fileExists(p) {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s is not installed (see https://tailscale.com/download)", name)
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

// StartTailscale builds the namespace and starts tailscaled in it.
// changed is called (from another goroutine) when the connection state
// changes.
func StartTailscale(s TailscaleSpec, log *slog.Logger, changed func()) (Device, error) {
	daemon, err := lookPath(tailscaledBinary)
	if err != nil {
		return nil, err
	}
	cli, err := lookPath(tailscaleBinary)
	if err != nil {
		return nil, err
	}
	t := &Tailscale{spec: s, log: log, changed: changed, sock: filepath.Join(s.RunDir, "tailscaled-"+s.Name+".sock"),
		stop: make(chan struct{}), done: make(chan struct{})}
	t.peerIf = "ts-" + s.Name
	if len(t.peerIf) > 15 {
		t.peerIf = t.peerIf[:15]
	}
	if t.peerIf == s.Iface {
		t.peerIf = "p" + t.peerIf[1:]
	}
	t.ns = -1
	t.killLeftover()
	if err := os.MkdirAll(s.StateDir, 0o700); err != nil {
		return nil, err
	}
	if err := t.setup(); err != nil {
		t.teardown()
		return nil, err
	}
	go t.loop(daemon, cli)
	return t, nil
}

func (t *Tailscale) pidFile() string {
	return filepath.Join(t.spec.RunDir, "tailscaled-"+t.spec.Name+".pid")
}

// killLeftover stops a tailscaled that survived a crash of shuntd.
func (t *Tailscale) killLeftover() {
	b, err := os.ReadFile(t.pidFile())
	if err != nil {
		return
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	if pid > 1 {
		cmd, _ := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
		if strings.Contains(string(cmd), "tailscaled") {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			t.log.Warn("killed leftover tailscaled", "tunnel", t.spec.Name, "pid", pid)
		}
	}
	_ = os.Remove(t.pidFile())
}

// inNS runs fn on a thread that is inside the namespace.
func inNS(ns netns.NsHandle, fn func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	orig, err := netns.Get()
	if err != nil {
		return err
	}
	defer orig.Close()
	if err := netns.Set(ns); err != nil {
		return err
	}
	defer func() { _ = netns.Set(orig) }() // never leave the thread inside
	return fn()
}

func writeSysctl(path, v string) error { return os.WriteFile(path, []byte(v), 0o644) }

// setup creates namespace, veth pair, addresses, forwarding and NAT.
func (t *Tailscale) setup() error {
	t.teardown() // leftovers of a crash
	host, peer := TailscaleAddrs(t.spec.Name)
	var ns netns.NsHandle
	err := func() error {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		orig, err := netns.Get()
		if err != nil {
			return err
		}
		defer orig.Close()
		ns, err = netns.New() // enters it
		_ = netns.Set(orig)
		return err
	}()
	if err != nil {
		return fmt.Errorf("network namespace: %w", err)
	}
	t.ns = ns

	la := netlink.NewLinkAttrs()
	la.Name = t.spec.Iface
	if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: la, PeerName: t.peerIf, PeerNamespace: netlink.NsFd(int(ns))}); err != nil {
		return fmt.Errorf("veth: %w", err)
	}
	link, err := netlink.LinkByName(t.spec.Iface)
	if err != nil {
		return err
	}
	if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: &net.IPNet{IP: host.AsSlice(), Mask: net.CIDRMask(30, 32)}}); err != nil {
		return err
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return err
	}
	// The firewall only forwards what arrives here; no global ip_forward.
	if err := writeSysctl("/proc/sys/net/ipv4/conf/"+t.spec.Iface+"/forwarding", "1"); err != nil {
		return fmt.Errorf("forwarding: %w", err)
	}

	h, err := netlink.NewHandleAt(ns)
	if err != nil {
		return err
	}
	defer h.Close()
	for _, name := range []string{"lo", t.peerIf} {
		l, err := h.LinkByName(name)
		if err != nil {
			return err
		}
		if name == t.peerIf {
			if err := h.AddrAdd(l, &netlink.Addr{IPNet: &net.IPNet{IP: peer.AsSlice(), Mask: net.CIDRMask(30, 32)}}); err != nil {
				return err
			}
		}
		if err := h.LinkSetUp(l); err != nil {
			return err
		}
	}
	pl, _ := h.LinkByName(t.peerIf)
	if err := h.RouteAdd(&netlink.Route{LinkIndex: pl.Attrs().Index, Gw: host.AsSlice()}); err != nil {
		return fmt.Errorf("default route in namespace: %w", err)
	}
	// With an exit node tailscaled sends even the local subnets into the
	// tailnet (table 52, rule 5270): the replies for the host would go
	// there instead of back over the veth. Ours comes first.
	rule := netlink.NewRule()
	rule.Dst = &net.IPNet{IP: host.AsSlice(), Mask: net.CIDRMask(30, 32)}
	rule.Dst.IP = rule.Dst.IP.Mask(rule.Dst.Mask)
	rule.Table, rule.Priority = unix.RT_TABLE_MAIN, 90
	if err := h.RuleAdd(rule); err != nil {
		return fmt.Errorf("rule in namespace: %w", err)
	}
	return inNS(ns, func() error {
		for k, v := range map[string]string{
			"/proc/sys/net/ipv4/ip_forward":             "1",
			"/proc/sys/net/ipv4/conf/all/rp_filter":     "0",
			"/proc/sys/net/ipv4/conf/default/rp_filter": "0",
		} {
			if err := writeSysctl(k, v); err != nil {
				return fmt.Errorf("sysctl %s: %w", k, err)
			}
		}
		// What leaves into the tailnet is NATed to the node's own address;
		// nothing from the tailnet may be forwarded to the host or beyond
		// (replies of our own connections excepted).
		rules := fmt.Sprintf(`table inet shunt_ts {
	chain post {
		type nat hook postrouting priority srcnat; policy accept;
		oifname %[1]q masquerade
	}
	chain mss {
		type filter hook postrouting priority mangle; policy accept;
		oifname %[1]q tcp flags syn / syn,rst tcp option maxseg size set rt mtu
	}
	chain fwd_drop {
		type filter hook forward priority filter; policy accept;
		ct state established,related accept
		iifname %[1]q drop
	}
}
`, nsTun)
		cmd := exec.Command("nft", "-f", "-")
		cmd.Stdin = strings.NewReader(rules)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("nft in namespace: %v: %s", err, bytes.TrimSpace(out))
		}
		return nil
	})
}

// teardown removes the veth and lets go of the namespace (both may be absent).
func (t *Tailscale) teardown() {
	if l, err := netlink.LinkByName(t.spec.Iface); err == nil {
		_ = netlink.LinkDel(l)
	}
	if t.ns.IsOpen() {
		_ = t.ns.Close()
	}
	t.ns = -1
}

// loop runs tailscaled, logs in, and follows its state until Down.
func (t *Tailscale) loop(daemon, cli string) {
	defer close(t.done)
	backoff := 5 * time.Second
	for {
		started := time.Now()
		err := t.runOnce(daemon, cli)
		t.setDown()
		select {
		case <-t.stop:
			return
		default:
		}
		if time.Since(started) > 2*time.Minute {
			backoff = 5 * time.Second
		}
		t.mu.Lock()
		if t.lastErr == "" && err != nil {
			t.lastErr = err.Error()
		}
		msg := t.lastErr
		t.mu.Unlock()
		t.log.Warn("tailscaled stopped, restarting", "tunnel", t.spec.Name, "in", backoff, "err", msg)
		select {
		case <-t.stop:
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, time.Minute)
	}
}

func (t *Tailscale) setLastErr(s string) {
	t.mu.Lock()
	t.lastErr = s
	t.mu.Unlock()
}

// runOnce starts tailscaled inside the namespace and returns when it ends.
func (t *Tailscale) runOnce(daemon, cli string) error {
	ns := t.ns
	if !ns.IsOpen() {
		return errors.New("network namespace gone")
	}
	_ = os.Remove(t.sock)
	cmd := exec.Command(daemon,
		"--tun="+nsTun, "--state="+filepath.Join(t.spec.StateDir, "tailscaled.state"),
		"--socket="+t.sock, "--port=0", "--no-logs-no-support")
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "TS_NO_LOGS_NO_SUPPORT=true"}
	var logbuf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &logbuf, &logbuf
	// the thread that forks stays locked: Pdeathsig fires when it exits
	startErr := make(chan error, 1)
	waitErr := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		orig, err := netns.Get()
		if err != nil {
			startErr <- err
			return
		}
		defer orig.Close()
		if err := netns.Set(ns); err != nil {
			startErr <- err
			return
		}
		err = cmd.Start()
		_ = netns.Set(orig)
		startErr <- err
		if err == nil {
			waitErr <- cmd.Wait()
		}
	}()
	if err := <-startErr; err != nil {
		return err
	}
	t.mu.Lock()
	t.proc = cmd.Process
	t.mu.Unlock()
	_ = os.WriteFile(t.pidFile(), []byte(strconv.Itoa(cmd.Process.Pid)), 0o600)
	defer os.Remove(t.pidFile())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go t.follow(ctx, cli)
	select {
	case err := <-waitErr:
		cancel()
		if tail := lastLines(logbuf.String(), 3); tail != "" {
			t.setLastErr("tailscaled: " + tail)
		}
		return err
	case <-t.stop:
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-waitErr:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-waitErr
		}
		return nil
	}
}

func lastLines(s string, n int) string {
	l := strings.Split(strings.TrimSpace(s), "\n")
	if len(l) > n {
		l = l[len(l)-n:]
	}
	return strings.Join(l, " | ")
}

// cli runs the tailscale command line tool against this tunnel's socket.
func (t *Tailscale) cli(ctx context.Context, bin string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, bin, append([]string{"--socket=" + t.sock}, args...)...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%v: %s", err, lastLines(string(out), 2))
	}
	return out, nil
}

// status is the part of `tailscale status --json` Shunt reads.
type tsStatus struct {
	BackendState   string
	Health         []string
	AuthURL        string
	ExitNodeStatus *struct {
		Online bool
		ID     string
	}
	Peer map[string]struct {
		HostName      string
		ExitNode      bool
		CurAddr       string
		Relay         string
		RxBytes       int64
		TxBytes       int64
		Online        bool
		LastHandshake time.Time
	}
}

func (t *Tailscale) upArgs() []string {
	c := t.spec.Conf
	a := []string{"up", "--reset", "--timeout=60s", "--netfilter-mode=off", "--accept-dns=false",
		"--accept-routes=false", "--shields-up", "--auth-key=" + c.AuthKey}
	if c.LoginServer != "" {
		a = append(a, "--login-server="+c.LoginServer)
	}
	if c.Hostname != "" {
		a = append(a, "--hostname="+c.Hostname)
	}
	if _, ok := c.ExitNodeAddr(); ok {
		a = append(a, "--exit-node="+c.ExitNode)
	}
	return a
}

// follow logs in and then polls the state until ctx ends.
func (t *Tailscale) follow(ctx context.Context, cli string) {
	// wait for the socket
	for i := 0; i < 100 && !fileExists(t.sock); i++ {
		select {
		case <-ctx.Done():
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
	upCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	_, err := t.cli(upCtx, cli, t.upArgs()...)
	cancel()
	if err != nil {
		if ctx.Err() == nil {
			t.setLastErr("login failed: " + strings.ReplaceAll(err.Error(), t.spec.Conf.AuthKey, "…"))
			t.log.Warn("tailscale up failed", "tunnel", t.spec.Name, "err", t.lastErrStr())
			// let the loop restart tailscaled: a wedged login does not heal
			t.mu.Lock()
			p := t.proc
			t.mu.Unlock()
			if p != nil {
				time.AfterFunc(30*time.Second, func() { _ = p.Signal(syscall.SIGTERM) })
			}
		}
		return
	}
	named := t.spec.Conf.ExitNode != "" && !isAddr(t.spec.Conf.ExitNode)
	for {
		stCtx, c := context.WithTimeout(ctx, 10*time.Second)
		out, err := t.cli(stCtx, cli, "status", "--json")
		c()
		if err == nil {
			var st tsStatus
			if json.Unmarshal(out, &st) == nil {
				if named && st.BackendState == "Running" && st.ExitNodeStatus == nil {
					// a name can only be resolved once the netmap is in
					if _, err := t.cli(stCtx, cli, "set", "--exit-node="+t.spec.Conf.ExitNode); err != nil {
						t.setLastErr("exit node: " + err.Error())
					}
				}
				t.update(&st)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(3 * time.Second):
		}
	}
}

func (t *Tailscale) lastErrStr() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.lastErr
}

func isAddr(s string) bool { _, err := netip.ParseAddr(s); return err == nil }

// update turns a status into connected/not connected.
func (t *Tailscale) update(st *tsStatus) {
	ok := st.BackendState == "Running"
	endpoint := ""
	if want := t.spec.Conf.ExitNode; ok && want != "" {
		ok = st.ExitNodeStatus != nil && st.ExitNodeStatus.Online
	}
	for _, p := range st.Peer {
		if p.ExitNode {
			endpoint = p.CurAddr
			if endpoint == "" && p.Relay != "" {
				endpoint = "relay " + p.Relay
			}
		}
	}
	msg := ""
	switch {
	case st.AuthURL != "" && st.BackendState != "Running":
		msg = "the key was not accepted, the server wants an interactive login"
	case st.BackendState == "NeedsLogin":
		msg = "not logged in (auth_key wrong, expired or used up?)"
	case !ok && len(st.Health) > 0:
		msg = st.Health[0]
	}
	notify := false
	t.mu.Lock()
	if ok != t.connected {
		t.connected, notify = ok, true
		if ok {
			t.since, t.lastErr = time.Now(), ""
		}
	}
	if endpoint != "" {
		t.endpoint = endpoint
	}
	if !ok && msg != "" {
		t.lastErr = msg
	}
	t.mu.Unlock()
	if notify {
		if ok {
			t.log.Info("tailscale connected", "tunnel", t.spec.Name, "exit", t.spec.Conf.ExitNode)
		}
		if t.changed != nil {
			t.changed()
		}
	}
}

func (t *Tailscale) setDown() {
	t.mu.Lock()
	was := t.connected
	t.connected, t.proc = false, nil
	t.mu.Unlock()
	if was && t.changed != nil {
		t.changed()
	}
}

// DriverName implements Device.
func (t *Tailscale) DriverName() string { return "tailscale" }

// Down stops tailscaled and removes veth and namespace.
func (t *Tailscale) Down() {
	select {
	case <-t.stop:
	default:
		close(t.stop)
	}
	t.mu.Lock()
	p := t.proc
	t.mu.Unlock()
	if p != nil {
		_ = p.Signal(syscall.SIGTERM)
	}
	select {
	case <-t.done:
	case <-time.After(10 * time.Second):
		t.mu.Lock()
		if t.proc != nil {
			_ = t.proc.Kill()
		}
		t.mu.Unlock()
		<-t.done
	}
	t.teardown()
}

// Alive implements Device: the loop restarts tailscaled itself.
func (t *Tailscale) Alive() bool { return true }

// Connected reports whether the tunnel is up (and the exit node, if one is
// configured, reachable).
func (t *Tailscale) Connected() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.connected
}

// Err implements Device.
func (t *Tailscale) Err() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.connected {
		return ""
	}
	return t.lastErr
}

// Status implements Device: one "peer", the tailnet; LastHandshake is the
// time the connection was established.
func (t *Tailscale) Status() ([]PeerStatus, error) {
	t.mu.Lock()
	ps := PeerStatus{Endpoint: t.endpoint}
	if t.connected {
		ps.LastHandshake = t.since
	}
	t.mu.Unlock()
	if l, err := netlink.LinkByName(t.spec.Iface); err == nil {
		if st := l.Attrs().Statistics; st != nil {
			// the veth also carries tailscaled's own encrypted packets
			ps.RxBytes, ps.TxBytes = int64(st.RxBytes), int64(st.TxBytes)
		}
	}
	return []PeerStatus{ps}, nil
}

// Reresolve implements Device; tailscaled does that itself.
func (t *Tailscale) Reresolve(time.Time) ([]string, error) { return nil, nil }

func (t *Tailscale) String() string { return fmt.Sprintf("tailscale(%s)", t.spec.Name) }
