package procapp

import (
	"bufio"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

func tcpOwner(a netip.AddrPort) string {
	inode, uid := socketInode(a)
	if inode == "" {
		return Unknown
	}
	// /proc/<pid>/fd of other users' processes is closed to a daemon without
	// CAP_SYS_PTRACE: then the user is all we can tell
	if name := ownerName(inode); name != "" {
		return name
	}
	return "uid-" + uid
}

func ownerName(inode string) string {
	want := "socket:[" + inode + "]"
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return ""
	}
	for _, e := range ents {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		fds, err := os.ReadDir("/proc/" + e.Name() + "/fd")
		if err != nil {
			continue
		}
		for _, fd := range fds {
			if l, err := os.Readlink("/proc/" + e.Name() + "/fd/" + fd.Name()); err == nil && l == want {
				b, err := os.ReadFile("/proc/" + e.Name() + "/comm")
				if err != nil {
					return ""
				}
				return strings.TrimSpace(string(b))
			}
		}
	}
	return ""
}

// socketInode looks the connection's local end up in /proc/net/tcp{,6}.
func socketInode(a netip.AddrPort) (inode, uid string) {
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		fh, err := os.Open(f)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(fh)
		sc.Scan() // header
		for sc.Scan() {
			fs := strings.Fields(sc.Text())
			if len(fs) < 10 {
				continue
			}
			if local, ok := parseAddr(fs[1]); ok && local == a {
				fh.Close()
				return fs[9], fs[7]
			}
		}
		fh.Close()
	}
	return "", ""
}

// parseAddr reads "0100007F:1F90" (IPv4) or the 32-hex-digit IPv6 form;
// the kernel prints each 32-bit word in host (little endian) order.
func parseAddr(s string) (netip.AddrPort, bool) {
	h, p, ok := strings.Cut(s, ":")
	if !ok {
		return netip.AddrPort{}, false
	}
	port, err := strconv.ParseUint(p, 16, 16)
	if err != nil || len(h)%8 != 0 || len(h) == 0 {
		return netip.AddrPort{}, false
	}
	var b []byte
	for i := 0; i < len(h); i += 8 {
		var w [4]byte
		for j := 0; j < 4; j++ {
			v, err := strconv.ParseUint(h[i+2*j:i+2*j+2], 16, 8)
			if err != nil {
				return netip.AddrPort{}, false
			}
			w[3-j] = byte(v)
		}
		b = append(b, w[:]...)
	}
	addr, ok := netip.AddrFromSlice(b)
	if !ok {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(addr.Unmap(), uint16(port)), true
}
