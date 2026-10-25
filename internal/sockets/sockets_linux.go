package sockets

import (
	"encoding/binary"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Bob-Nixkoenner/the_shunt/internal/cgroup"
)

const (
	sockDiagByFamily = 20
	diagAttrCgroupID = 21 // INET_DIAG_CGROUP_ID (kernel 5.7+)
	diagAttrV6Only   = 11 // INET_DIAG_SKV6ONLY
	sizeofReq        = 56 // inet_diag_req_v2
	sizeofMsg        = 72 // inet_diag_msg
)

// Dump lists the sockets of proto ("tcp" or "udp") in the given states (a
// bit mask of 1<<State, 0 = all), IPv4 and IPv6.
func Dump(proto string, states uint32) ([]Socket, error) {
	var p uint8
	switch proto {
	case "tcp":
		p = unix.IPPROTO_TCP
	case "udp":
		p = unix.IPPROTO_UDP
	default:
		return nil, fmt.Errorf("sockets: unknown protocol %q", proto)
	}
	if states == 0 {
		states = ^uint32(0)
	}
	var out []Socket
	for _, fam := range []uint8{unix.AF_INET, unix.AF_INET6} {
		s, err := dump(fam, p, states)
		if err != nil {
			return nil, err
		}
		for i := range s {
			s[i].Proto = proto
		}
		out = append(out, s...)
	}
	return out, nil
}

func dump(family, proto uint8, states uint32) ([]Socket, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return nil, fmt.Errorf("sock_diag: %w", err)
	}
	defer unix.Close(fd)
	req := make([]byte, unix.NLMSG_HDRLEN+sizeofReq)
	ne := binary.NativeEndian
	ne.PutUint32(req[0:], uint32(len(req)))
	ne.PutUint16(req[4:], sockDiagByFamily)
	ne.PutUint16(req[6:], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	ne.PutUint32(req[8:], 1)
	b := req[unix.NLMSG_HDRLEN:]
	b[0], b[1] = family, proto
	ne.PutUint32(b[4:], states)
	if err := unix.Sendto(fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("sock_diag send: %w", err)
	}
	var out []Socket
	buf := make([]byte, 1<<16)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			return nil, fmt.Errorf("sock_diag receive: %w", err)
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return nil, fmt.Errorf("sock_diag parse: %w", err)
		}
		for _, m := range msgs {
			switch m.Header.Type {
			case unix.NLMSG_DONE:
				return out, nil
			case unix.NLMSG_ERROR:
				if len(m.Data) >= 4 {
					if e := int32(ne.Uint32(m.Data)); e != 0 {
						return nil, fmt.Errorf("sock_diag: %w", syscall.Errno(-e))
					}
				}
				return out, nil
			}
			if s, ok := parseMsg(m.Data); ok {
				out = append(out, s)
			}
		}
	}
}

// parseMsg decodes an inet_diag_msg and the attributes after it.
func parseMsg(b []byte) (Socket, bool) {
	if len(b) < sizeofMsg {
		return Socket{}, false
	}
	be, ne := binary.BigEndian, binary.NativeEndian
	s := Socket{State: b[1]}
	addr := func(raw []byte) netip.Addr {
		if b[0] == unix.AF_INET {
			return netip.AddrFrom4([4]byte(raw[:4]))
		}
		return netip.AddrFrom16([16]byte(raw[:16]))
	}
	// inet_diag_sockid at 4: sport, dport (big endian), src[16], dst[16], if, cookie
	s.Local = netip.AddrPortFrom(addr(b[8:24]), be.Uint16(b[4:]))
	s.Remote = netip.AddrPortFrom(addr(b[24:40]), be.Uint16(b[6:]))
	s.Iface = int(ne.Uint32(b[40:]))
	s.UID = ne.Uint32(b[64:])
	s.Inode = ne.Uint32(b[68:])
	for a := b[sizeofMsg:]; len(a) >= 4; {
		l, t := int(ne.Uint16(a)), ne.Uint16(a[2:])&0x3fff
		if l < 4 || l > len(a) {
			break
		}
		v := a[4:l]
		switch {
		case t == diagAttrCgroupID && len(v) >= 8:
			s.Cgroup = ne.Uint64(v)
		case t == diagAttrV6Only && len(v) >= 1:
			s.V6Only = v[0] != 0
		}
		a = a[min((l+3)&^3, len(a)):]
	}
	return s, true
}

// ListListening returns the TCP and UDP sockets that wait for peers.
func ListListening() ([]Socket, error) {
	tcp, err := Dump("tcp", 1<<StateListen)
	if err != nil {
		return nil, err
	}
	udp, err := Dump("udp", 1<<StateClose)
	if err != nil {
		return nil, err
	}
	out := tcp
	for _, s := range udp {
		if s.Listening() {
			out = append(out, s)
		}
	}
	return out, nil
}

// Resolver maps sockets to their owners. It caches the cgroup tree and the
// owner of each cgroup for a few seconds. Safe for concurrent use.
type Resolver struct {
	mu      sync.Mutex
	mount   string
	paths   map[uint64]string
	scanned time.Time
	owners  map[uint64]cached
}

type cached struct {
	o  Owner
	at time.Time
}

// ownerTTL: how long a cgroup's owner (its process names) is reused.
const ownerTTL = 10 * time.Second

// Owner returns the owner of the cgroup with id cg ("" Name = unknown).
func (r *Resolver) Owner(cg uint64) Owner {
	if cg == 0 {
		return Owner{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.owners[cg]; ok && time.Since(c.at) < ownerTTL {
		return c.o
	}
	p, ok := r.paths[cg]
	if !ok && time.Since(r.scanned) > time.Second {
		r.scan()
		p, ok = r.paths[cg]
	}
	if !ok {
		return Owner{}
	}
	if p == "" {
		// the root cgroup: sockets the kernel opened itself (WireGuard,
		// NFS), owned by no process
		return Owner{Name: "kernel", System: true}
	}
	o, shared := nameOf(p)
	o.Shared = shared
	o.Procs = r.procs(p)
	if o.Name == "" && len(o.Procs) > 0 {
		o.Name = o.Procs[0]
	}
	if r.owners == nil || len(r.owners) > 4096 {
		r.owners = map[uint64]cached{}
	}
	r.owners[cg] = cached{o, time.Now()}
	return o
}

// scan walks the cgroup tree: directory inode = cgroup id.
func (r *Resolver) scan() {
	r.scanned = time.Now()
	if r.mount == "" {
		m, err := cgroup.Mount()
		if err != nil {
			return
		}
		r.mount = m
	}
	paths := map[uint64]string{}
	_ = filepath.WalkDir(r.mount, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		var st unix.Stat_t
		if unix.Stat(p, &st) == nil {
			rel, _ := filepath.Rel(r.mount, p)
			if rel == "." {
				rel = ""
			}
			paths[st.Ino] = rel
		}
		return nil
	})
	r.paths = paths
}

// procs returns the distinct names of the oldest few processes in cgroup
// rel, oldest first (the app before its helpers).
func (r *Resolver) procs(rel string) []string {
	raw, err := os.ReadFile(filepath.Join(r.mount, rel, "cgroup.procs"))
	if err != nil {
		return nil
	}
	var pids []int
	for _, f := range strings.Fields(string(raw)) {
		if pid, err := strconv.Atoi(f); err == nil {
			pids = append(pids, pid)
		}
	}
	slices.Sort(pids)
	var out []string
	for _, pid := range pids {
		c, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm")
		if err != nil {
			continue
		}
		if n := strings.TrimSpace(string(c)); n != "" && !slices.Contains(out, n) {
			out = append(out, n)
			if len(out) == 5 {
				break
			}
		}
	}
	return out
}

// Of finds the socket of proto whose local address is from (the source of
// a packet that arrived here, e.g. a DNS query) and returns its owner. An
// unconnected socket bound to the wildcard address matches too.
func (r *Resolver) Of(proto string, from netip.AddrPort) (Owner, bool) {
	ss, err := Dump(proto, 0)
	if err != nil {
		return Owner{}, false
	}
	from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
	best := -1
	for i, s := range ss {
		if s.Local.Port() != from.Port() || s.Cgroup == 0 {
			continue
		}
		a := s.Local.Addr().Unmap()
		if a == from.Addr() {
			best = i
			break
		}
		if a.IsUnspecified() && best < 0 {
			best = i
		}
	}
	if best < 0 {
		return Owner{}, false
	}
	o := r.Owner(ss[best].Cgroup)
	return o, o.Name != ""
}
