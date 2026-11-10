package tunnel

import (
	"bufio"
	"encoding/hex"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
)

// After a network change (Wi-Fi reconnected with a new random MAC, roaming,
// a new DHCP lease) the machine may have a new address. openvpn over UDP
// does not care: its socket is not bound to an address, the next packet
// leaves from the new one and the server follows ("float"). openvpn over TCP
// does: its connection stays tied to the old source address, nothing goes
// out any more, and openvpn only notices at its ping-restart (60 s with the
// usual keepalive 10 60). CheckNetwork finds that case and restarts the
// connection at once.

// procRoot is a variable for tests.
var procRoot = "/proc"

// ovpnSock is one of openvpn's sockets.
type ovpnSock struct {
	TCP   bool
	Local netip.Addr // unspecified for an unbound UDP socket
}

// netAction is what CheckNetwork does.
type netAction int

const (
	netNothing netAction = iota
	netRearm             // the addresses changed: watch the tunnel for a stall again
	netRestart           // a socket's source address is gone: reconnect now
)

// decideNetAction: a socket (TCP, or UDP bound to an address) whose source
// address the machine no longer has cannot carry anything; restart. Otherwise
// a change of the machine's addresses only re-arms watchStall (an unbound UDP
// socket follows by itself, and if the server does not float the stall
// watcher catches it within seconds). Nothing changed: nothing to do.
func decideNetAction(socks []ovpnSock, host []netip.Addr, hostChanged bool) netAction {
	for _, s := range socks {
		if !s.Local.IsValid() || s.Local.IsUnspecified() {
			continue
		}
		if !slices.Contains(host, s.Local) {
			return netRestart
		}
	}
	if hostChanged {
		return netRearm
	}
	return netNothing
}

// hostAddrs returns the machine's addresses (all interfaces).
func hostAddrs() ([]netip.Addr, bool) {
	as, err := netlink.AddrList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return nil, false
	}
	out := make([]netip.Addr, 0, len(as))
	for _, a := range as {
		if ip, ok := netip.AddrFromSlice(a.IP); ok {
			out = append(out, ip.Unmap())
		}
	}
	slices.SortFunc(out, func(a, b netip.Addr) int { return a.Compare(b) })
	return slices.Compact(out), true
}

// procSockets returns the TCP (connected or connecting) and UDP sockets of
// process pid, read from /proc.
func procSockets(pid int) []ovpnSock {
	base := filepath.Join(procRoot, strconv.Itoa(pid))
	fds, err := os.ReadDir(filepath.Join(base, "fd"))
	if err != nil {
		return nil
	}
	inodes := map[string]bool{}
	for _, fd := range fds {
		l, err := os.Readlink(filepath.Join(base, "fd", fd.Name()))
		if err != nil {
			continue
		}
		if in, ok := strings.CutPrefix(l, "socket:["); ok {
			inodes[strings.TrimSuffix(in, "]")] = true
		}
	}
	if len(inodes) == 0 {
		return nil
	}
	var out []ovpnSock
	for _, f := range []string{"tcp", "tcp6", "udp", "udp6"} {
		out = append(out, readSockTable(filepath.Join(base, "net", f), strings.HasPrefix(f, "tcp"), inodes)...)
	}
	return out
}

// readSockTable reads one /proc/net/{tcp,udp}[6] table and keeps the
// sockets in inodes. For TCP only established and connecting sockets count
// (a listening one has no source address that could go stale).
func readSockTable(path string, tcp bool, inodes map[string]bool) []ovpnSock {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []ovpnSock
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fl := strings.Fields(sc.Text())
		if len(fl) < 10 || !inodes[fl[9]] {
			continue
		}
		if tcp && fl[3] != "01" && fl[3] != "02" { // ESTABLISHED, SYN_SENT
			continue
		}
		hostPart, _, _ := strings.Cut(fl[1], ":")
		a, ok := parseProcAddr(hostPart)
		if !ok {
			continue
		}
		out = append(out, ovpnSock{TCP: tcp, Local: a})
	}
	return out
}

// parseProcAddr decodes the address of /proc/net/tcp: 32-bit words in host
// (little-endian) byte order, one for IPv4, four for IPv6.
func parseProcAddr(h string) (netip.Addr, bool) {
	b, err := hex.DecodeString(h)
	if err != nil || (len(b) != 4 && len(b) != 16) {
		return netip.Addr{}, false
	}
	for i := 0; i < len(b); i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	a, _ := netip.AddrFromSlice(b)
	return a.Unmap(), true
}

// netRestartPause keeps CheckNetwork from restarting again while the last
// restart is still reconnecting (events come in bursts).
var netRestartPause = 20 * time.Second

// CheckNetwork compares openvpn's sockets with the machine's addresses; the
// daemon calls it on every network tick. A source address that is gone on
// two checks in a row (a reconnect that gets the same lease back keeps the
// TCP connection alive) restarts the connection with SIGUSR1, like
// watchStall; the next "Initialization Sequence Completed" arms watchStall
// again. Changed addresses alone re-arm watchStall.
func (o *OpenVPN) CheckNetwork() {
	host, ok := hostAddrs()
	if !ok {
		return
	}
	key := ""
	for _, a := range host {
		key += a.String() + " "
	}
	o.mu.Lock()
	p, connected := o.proc, o.connected
	changed := o.hostKey != "" && key != o.hostKey
	o.hostKey = key
	o.mu.Unlock()
	if p == nil || !connected {
		o.mu.Lock()
		o.staleSeen = false
		o.mu.Unlock()
		return
	}
	act := decideNetAction(procSockets(p.Pid), host, changed)
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.proc != p || !o.connected {
		return
	}
	switch act {
	case netRestart:
		if !o.staleSeen {
			o.staleSeen = true // confirm on the next tick
			o.armStall()
			return
		}
		if time.Since(o.netKick) < netRestartPause {
			return
		}
		o.staleSeen, o.netKick = false, time.Now()
		o.watch++ // a running watchStall must not restart it a second time
		o.log.Warn("openvpn: the connection's source address is gone (network changed), reconnecting", "tunnel", o.spec.Name)
		_ = p.Signal(syscall.SIGUSR1)
	case netRearm:
		o.staleSeen = false
		o.armStall()
	default:
		o.staleSeen = false
	}
}
