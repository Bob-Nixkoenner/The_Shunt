//go:build linux

// Package ovpndroid runs an OpenVPN tunnel behind the Android app's one TUN:
// the openvpn program (built with TARGET_ANDROID, android/build-openvpn.sh)
// does not open a tun device itself but asks its management client for one
// (doc/android.txt in OpenVPN). We are that client and hand it one end of a
// datagram socket pair instead of a real TUN; the other end feeds a gVisor
// netstack, whose Net the split stack dials through – like a WireGuard tunnel.
//
//	app ─► split stack ─► Net (gVisor) ⇄ socket pair ⇄ openvpn ─► UDP/TCP out
//
// openvpn runs under the app's UID, which is excluded from the app's own VPN,
// so its sockets go out over the real network (PROTECTFD is answered too).
package ovpndroid

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// Options for Start.
type Options struct {
	Exe    string // the openvpn program (libopenvpn.so in the app's library folder)
	Config string // .ovpn text, inline only (no file references), already checked
	Dir    string // private work folder: config file and management socket
	User   string // for auth-user-pass
	Pass   string
	MTU    int // of the netstack; 0 = 1280
	// Protect excludes a socket of openvpn from the VPN (VpnService.protect);
	// nil: not needed (openvpn's UID is outside the VPN anyway).
	Protect func(fd int) bool
	Logf    func(format string, args ...any)
}

// Tunnel is one running openvpn.
type Tunnel struct {
	o    Options
	cmd  *exec.Cmd
	ln   *net.UnixListener
	wmu  sync.Mutex // guards mgmt and writes to it
	mgmt *net.UnixConn
	done chan struct{} // closed when openvpn has ended
	err  error

	mu        sync.Mutex
	net       *netstack.Net
	dev       tun.Device
	pair      *os.File // our end of the socket pair
	local     []netip.Addr
	dns       []netip.Addr
	pendLocal []netip.Addr // from IFCONFIG/IFCONFIG6, used at OPENTUN
	pendDNS   []netip.Addr
	connected bool
	rx, tx    int64
	ready     chan struct{} // closed on the first CONNECTED
	readyOnce sync.Once
}

// Start launches openvpn and returns at once; Ready() tells when the tunnel
// is up, Done() when openvpn ended (Err() says why).
func Start(o Options) (*Tunnel, error) {
	if o.MTU == 0 {
		o.MTU = 1280
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	var err error
	if o.Dir, err = filepath.Abs(o.Dir); err != nil { // openvpn runs inside it
		return nil, err
	}
	if o.Exe, err = filepath.Abs(o.Exe); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(o.Dir, 0o700); err != nil {
		return nil, err
	}
	conf := filepath.Join(o.Dir, "tunnel.ovpn")
	if err := os.WriteFile(conf, []byte(o.Config), 0o600); err != nil {
		return nil, err
	}
	sock := filepath.Join(o.Dir, "mgmt")
	os.Remove(sock)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		return nil, err
	}
	t := &Tunnel{o: o, ln: ln, done: make(chan struct{}), ready: make(chan struct{})}
	t.cmd = exec.Command(o.Exe,
		"--config", conf,
		"--management", sock, "unix", "--management-client",
		"--management-hold", "--management-query-passwords",
		"--persist-tun", // reconnects keep the tun (PERSIST_TUN_ACTION)
		"--verb", "3")
	t.cmd.Dir = o.Dir
	out, _ := t.cmd.StdoutPipe()
	t.cmd.Stderr = t.cmd.Stdout
	if err := t.cmd.Start(); err != nil {
		ln.Close()
		return nil, fmt.Errorf("start openvpn: %w", err)
	}
	go t.copyLog(out)
	go t.run()
	return t, nil
}

func (t *Tunnel) copyLog(r interface{ Read([]byte) (int, error) }) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		t.o.Logf("openvpn: %s", sc.Text())
	}
}

// run accepts the management connection and serves it until openvpn ends.
func (t *Tunnel) run() {
	exited := make(chan error, 1)
	go func() { exited <- t.cmd.Wait() }()
	accepted := make(chan *net.UnixConn, 1)
	go func() {
		c, err := t.ln.AcceptUnix()
		if err == nil {
			accepted <- c
		}
	}()
	select {
	case c := <-accepted:
		t.wmu.Lock()
		t.mgmt = c
		t.wmu.Unlock()
		t.ln.Close()
		os.Remove(filepath.Join(t.o.Dir, "mgmt"))
		err := t.serve()
		t.finish(<-exited, err)
	case err := <-exited:
		t.ln.Close()
		t.finish(err, errors.New("openvpn ended before it connected to the management socket"))
	case <-time.After(15 * time.Second):
		t.cmd.Process.Kill()
		t.finish(<-exited, errors.New("openvpn did not connect to the management socket"))
	}
}

func (t *Tunnel) finish(exitErr, err error) {
	if err == nil {
		err = exitErr
	}
	if err == nil {
		err = errors.New("openvpn ended")
	}
	t.err = err
	t.mu.Lock()
	t.connected = false
	t.closeStack()
	t.mu.Unlock()
	close(t.done)
}

// serve reads management messages (lines, some with an fd attached).
func (t *Tunnel) serve() error {
	t.send("state on")
	t.send("bytecount 5")
	var fds []int
	defer func() {
		for _, fd := range fds {
			unix.Close(fd)
		}
	}()
	buf := make([]byte, 64<<10)
	oob := make([]byte, unix.CmsgSpace(4*8))
	var pend []byte
	for {
		n, oobn, _, _, err := t.mgmt.ReadMsgUnix(buf, oob)
		if err != nil {
			return nil // openvpn closed it: run() reports the exit
		}
		if oobn > 0 {
			if msgs, err := unix.ParseSocketControlMessage(oob[:oobn]); err == nil {
				for _, m := range msgs {
					if r, err := unix.ParseUnixRights(&m); err == nil {
						fds = append(fds, r...)
					}
				}
			}
		}
		pend = append(pend, buf[:n]...)
		for {
			i := strings.IndexByte(string(pend), '\n')
			if i < 0 {
				break
			}
			line := strings.TrimRight(string(pend[:i]), "\r")
			pend = pend[i+1:]
			// a socket to protect comes either with a question (new socket) or,
			// after "network-change", with a notice (socket kept)
			notice := strings.HasPrefix(line, "PROTECTFD:")
			if strings.HasPrefix(line, ">NEED-OK:Need 'PROTECTFD'") || notice {
				if len(fds) > 0 {
					fd := fds[0]
					fds = fds[1:]
					if t.o.Protect != nil {
						t.o.Protect(fd)
					}
					unix.Close(fd)
				}
				if !notice {
					t.send("needok 'PROTECTFD' ok")
				}
				continue
			}
			if err := t.handle(line); err != nil {
				return err
			}
		}
	}
}

// handle answers one management line.
func (t *Tunnel) handle(line string) error {
	switch {
	case strings.HasPrefix(line, ">HOLD:"):
		t.send("hold release")
	case strings.HasPrefix(line, ">NEED-OK:"):
		what, msg := needOK(line)
		switch what {
		case "IFCONFIG": // local netmask/remote mtu topology
			if f := strings.Fields(msg); len(f) > 0 {
				if a, err := netip.ParseAddr(f[0]); err == nil {
					t.mu.Lock()
					t.pendLocal = append(t.pendLocal, a)
					t.mu.Unlock()
				}
			}
			t.send("needok 'IFCONFIG' ok")
		case "IFCONFIG6": // addr/bits
			if p, err := netip.ParsePrefix(strings.TrimSpace(msg)); err == nil {
				t.mu.Lock()
				t.pendLocal = append(t.pendLocal, p.Addr())
				t.mu.Unlock()
			}
			t.send("needok 'IFCONFIG6' ok")
		case "DNSSERVER", "DNS6SERVER":
			if a, err := netip.ParseAddr(strings.TrimSpace(msg)); err == nil {
				t.mu.Lock()
				t.pendDNS = append(t.pendDNS, a)
				t.mu.Unlock()
			}
			t.send("needok '" + what + "' ok")
		case "PERSIST_TUN_ACTION":
			// same addresses: keep our socket pair and netstack
			t.mu.Lock()
			same := t.dev != nil && sameAddrs(t.local, t.pendLocal)
			t.mu.Unlock()
			if same {
				t.mu.Lock()
				t.pendLocal, t.pendDNS = nil, nil
				t.mu.Unlock()
				t.send("needok 'PERSIST_TUN_ACTION' NOACTION")
			} else {
				t.send("needok 'PERSIST_TUN_ACTION' OPEN_BEFORE_CLOSE")
			}
		case "OPENTUN":
			fd, err := t.openTun()
			if err != nil {
				t.o.Logf("openvpn tun: %v", err)
				t.send("needok 'OPENTUN' cancel")
				return nil
			}
			t.wmu.Lock()
			_, _, err = t.mgmt.WriteMsgUnix([]byte("needok 'OPENTUN' ok\n"), unix.UnixRights(fd), nil)
			t.wmu.Unlock()
			unix.Close(fd) // openvpn has its own copy now
			if err != nil {
				return err
			}
		default: // ROUTE, ROUTE6, DNSDOMAIN, …: the split stack routes by itself
			t.send("needok '" + what + "' ok")
		}
	case strings.HasPrefix(line, ">PASSWORD:Need 'Auth'"):
		t.send(fmt.Sprintf("username \"Auth\" %s", quote(t.o.User)))
		t.send(fmt.Sprintf("password \"Auth\" %s", quote(t.o.Pass)))
	case strings.HasPrefix(line, ">PASSWORD:Need 'Private Key'"):
		t.send(fmt.Sprintf("password \"Private Key\" %s", quote(t.o.Pass)))
	case strings.HasPrefix(line, ">PASSWORD:Verification Failed"):
		t.send("signal SIGTERM")
		return errors.New("login refused by the server (" + strings.TrimPrefix(line, ">PASSWORD:") + ")")
	case strings.HasPrefix(line, ">STATE:"):
		// >STATE:time,NAME,detail,local,remote,…
		f := strings.Split(strings.TrimPrefix(line, ">STATE:"), ",")
		if len(f) > 1 {
			t.mu.Lock()
			t.connected = f[1] == "CONNECTED"
			t.mu.Unlock()
			if f[1] == "CONNECTED" {
				t.readyOnce.Do(func() { close(t.ready) })
			}
			t.o.Logf("openvpn state %s", f[1])
		}
	case strings.HasPrefix(line, ">BYTECOUNT:"):
		f := strings.Split(strings.TrimPrefix(line, ">BYTECOUNT:"), ",")
		if len(f) == 2 {
			rx, _ := strconv.ParseInt(f[0], 10, 64)
			tx, _ := strconv.ParseInt(f[1], 10, 64)
			t.mu.Lock()
			t.rx, t.tx = rx, tx
			t.mu.Unlock()
		}
	case strings.HasPrefix(line, ">FATAL:"):
		return errors.New(strings.TrimPrefix(line, ">FATAL:"))
	}
	return nil
}

// needOK splits ">NEED-OK:Need 'WHAT' confirmation MSG:text".
func needOK(line string) (what, msg string) {
	if i := strings.IndexByte(line, '\''); i >= 0 {
		if j := strings.IndexByte(line[i+1:], '\''); j >= 0 {
			what = line[i+1 : i+1+j]
		}
	}
	if i := strings.Index(line, "MSG:"); i >= 0 {
		msg = line[i+4:]
	}
	return what, msg
}

// openTun makes the socket pair and the netstack for the collected
// addresses; it returns openvpn's end.
func (t *Tunnel) openTun() (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.pendLocal) == 0 {
		return -1, errors.New("server sent no address")
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, fd := range fds {
		unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, 1<<20)
		unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 1<<20)
	}
	dev, tnet, err := netstack.CreateNetTUN(t.pendLocal, t.pendDNS, t.o.MTU)
	if err != nil {
		unix.Close(fds[0])
		unix.Close(fds[1])
		return -1, err
	}
	t.closeStack() // OPEN_BEFORE_CLOSE: the old one goes now
	t.dev, t.net, t.pair = dev, tnet, os.NewFile(uintptr(fds[0]), "ovpn-tun")
	t.local, t.dns = t.pendLocal, t.pendDNS
	t.pendLocal, t.pendDNS = nil, nil
	go pump(t.pair, dev, t.o.MTU)
	t.o.Logf("openvpn tun: %v, DNS %v", t.local, t.dns)
	return fds[1], nil
}

// pump moves packets between the socket pair and the netstack until one closes.
func pump(pair *os.File, dev tun.Device, mtu int) {
	go func() {
		b := make([]byte, 65535)
		for {
			n, err := pair.Read(b)
			if err != nil {
				return
			}
			if _, err := dev.Write([][]byte{b[:n]}, 0); err != nil {
				return
			}
		}
	}()
	bufs := [][]byte{make([]byte, mtu+64)}
	sizes := []int{0}
	for {
		n, err := dev.Read(bufs, sizes, 0)
		if err != nil {
			return
		}
		for i := 0; i < n; i++ {
			if _, err := pair.Write(bufs[i][:sizes[i]]); err != nil && !errors.Is(err, unix.ENOBUFS) {
				return
			}
		}
	}
}

func (t *Tunnel) closeStack() { // with t.mu
	if t.pair != nil {
		t.pair.Close()
		t.pair = nil
	}
	if t.dev != nil {
		t.dev.Close()
		t.dev, t.net = nil, nil
	}
}

// send writes a management command; before openvpn connected it is dropped.
func (t *Tunnel) send(cmd string) bool {
	t.wmu.Lock()
	defer t.wmu.Unlock()
	if t.mgmt == nil {
		return false
	}
	_, err := t.mgmt.Write([]byte(cmd + "\n"))
	return err == nil
}

// quote for the management interface: double quotes, \ and " escaped.
func quote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

func sameAddrs(a, b []netip.Addr) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Net is the tunnel's network to dial through; nil while it has no tun.
func (t *Tunnel) Net() *netstack.Net {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.connected {
		return nil
	}
	return t.net
}

// Addrs are the tunnel's own addresses (pushed by the server).
func (t *Tunnel) Addrs() []netip.Addr {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]netip.Addr(nil), t.local...)
}

// DNS are the DNS servers the server pushed.
func (t *Tunnel) DNS() []netip.Addr {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]netip.Addr(nil), t.dns...)
}

// Connected reports whether openvpn says CONNECTED.
func (t *Tunnel) Connected() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.connected
}

// Bytes are openvpn's counters (updated every 5 s).
func (t *Tunnel) Bytes() (rx, tx int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.rx, t.tx
}

// Pid is the openvpn process ID.
func (t *Tunnel) Pid() int { return t.cmd.Process.Pid }

// Ready is closed once the tunnel connected the first time.
func (t *Tunnel) Ready() <-chan struct{} { return t.ready }

// Done is closed when openvpn ended; Err tells why.
func (t *Tunnel) Done() <-chan struct{} { return t.done }

// Err is why openvpn ended (after Done).
func (t *Tunnel) Err() error { return t.err }

// Reconnect asks openvpn to reconnect (new socket, endpoints resolved again).
func (t *Tunnel) Reconnect() { t.send("signal SIGUSR1") }

// NetworkChanged tells openvpn the physical network changed (Wi-Fi <->
// mobile data): it reconnects at once instead of waiting for its ping
// timeout. Same command as "OpenVPN for Android".
func (t *Tunnel) NetworkChanged() { t.send("network-change") }

// Close stops openvpn (SIGTERM over management, then kill).
func (t *Tunnel) Close() {
	select {
	case <-t.done:
		return
	default:
	}
	t.send("signal SIGTERM")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	select {
	case <-t.done:
	case <-ctx.Done():
		t.cmd.Process.Kill()
		<-t.done
	}
}
