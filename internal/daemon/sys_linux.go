package daemon

import (
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/Bob-Nixkoenner/the_shunt/internal/links"
)

// selfExe is shuntd's own binary, also after an update replaced the file.
func selfExe() string { return "/proc/self/exe" }

// listenPrivate creates the API socket accessible by root only (the
// caller then opens it up for the socket group).
func listenPrivate(sock string) (net.Listener, error) {
	old := unix.Umask(0o177)
	defer unix.Umask(old)
	return net.Listen("unix", sock)
}

// peerCred returns the pid and uid of the process on the other end of a
// unix socket (SO_PEERCRED, set by the kernel: cannot be faked).
func peerCred(c net.Conn) (pid, uid uint32, ok bool) {
	uc, isUnix := c.(*net.UnixConn)
	if !isUnix {
		return 0, 0, false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, 0, false
	}
	var cred *unix.Ucred
	_ = raw.Control(func(fd uintptr) {
		cred, _ = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if cred == nil {
		return 0, 0, false
	}
	return uint32(cred.Pid), cred.Uid, true
}

// otherFirewalls names the packet filters besides The Shunt: ufw,
// firewalld and nftables tables of others (iptables-nft shows as ip filter).
func otherFirewalls() []string {
	var out []string
	if raw, err := os.ReadFile("/etc/ufw/ufw.conf"); err == nil && regexp.MustCompile(`(?m)^\s*ENABLED\s*=\s*yes`).Match(raw) {
		out = append(out, "ufw")
	}
	if _, err := os.Stat("/run/firewalld/firewalld.pid"); err == nil {
		out = append(out, "firewalld")
	}
	raw, err := exec.Command("nft", "list", "tables").Output()
	if err != nil {
		return out
	}
	for _, l := range strings.Split(string(raw), "\n") {
		t, ok := strings.CutPrefix(strings.TrimSpace(l), "table ")
		if _, name, _ := strings.Cut(t, " "); !ok || name == "shunt" || strings.HasPrefix(name, "shunt_") {
			continue
		}
		out = append(out, "nft "+t)
	}
	return out
}

// physicalIface: Wi-Fi, cable or mobile, not a bridge, tunnel or container.
func physicalIface(name string) bool { return links.Kind("/sys/class/net", name) != "" }

const tcpTimestampsFile = "/proc/sys/net/ipv4/tcp_timestamps"

// tcpTimestamps reads the system value ("" when unknown).
func tcpTimestamps() string {
	b, err := os.ReadFile(tcpTimestampsFile)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func setTCPTimestamps(v string) error { return os.WriteFile(tcpTimestampsFile, []byte(v), 0) }
