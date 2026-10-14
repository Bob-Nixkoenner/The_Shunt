package winsplit

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi                = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable = iphlpapi.NewProc("GetExtendedUdpTable")
)

const (
	tcpTableOwnerPIDAll = 5 // TCP_TABLE_OWNER_PID_ALL
	udpTableOwnerPID    = 1 // UDP_TABLE_OWNER_PID
)

// table calls GetExtendedTcpTable/-UdpTable, growing the buffer as asked.
func table(proc *windows.LazyProc, af uint32, class uint32) ([]byte, error) {
	size := uint32(16 << 10)
	for range 5 {
		buf := make([]byte, size)
		r, _, _ := proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, uintptr(af), uintptr(class), 0)
		switch syscall.Errno(r) {
		case 0:
			return buf[:size], nil
		case windows.ERROR_INSUFFICIENT_BUFFER:
			size += 4 << 10 // the table may grow between the calls
			continue
		default:
			return nil, fmt.Errorf("%s: %w", proc.Name, syscall.Errno(r))
		}
	}
	return nil, fmt.Errorf("%s: table keeps growing", proc.Name)
}

func rows(proto int, v6 bool) ([]Row, error) {
	af := uint32(windows.AF_INET)
	if v6 {
		af = windows.AF_INET6
	}
	if proto == 6 {
		b, err := table(procGetExtendedTcpTable, af, tcpTableOwnerPIDAll)
		if err != nil {
			return nil, err
		}
		if v6 {
			return parseTCP6(b)
		}
		return parseTCP4(b)
	}
	b, err := table(procGetExtendedUdpTable, af, udpTableOwnerPID)
	if err != nil {
		return nil, err
	}
	if v6 {
		return parseUDP6(b)
	}
	return parseUDP4(b)
}

// Owners finds the program behind a connection seen on the TUN. Its Owner
// method fits splitstack.Options.Owner; app IDs are lower-case exe paths.
type Owners struct {
	mu    sync.Mutex
	paths map[uint32]cached // PID -> exe path
}

type cached struct {
	path string
	at   time.Time
}

func NewOwners() *Owners { return &Owners{paths: map[uint32]cached{}} }

// Owner returns the exe path of the process owning src (the app's end of
// the connection), or "".
func (o *Owners) Owner(proto int, src, _ netip.AddrPort) string {
	rs, err := rows(proto, src.Addr().Is6())
	if err != nil {
		return ""
	}
	pid, ok := find(rs, src)
	if !ok {
		return ""
	}
	return o.path(pid)
}

func (o *Owners) path(pid uint32) string {
	o.mu.Lock()
	defer o.mu.Unlock()
	if c, ok := o.paths[pid]; ok && time.Since(c.at) < time.Minute { // PIDs get reused
		return c.path
	}
	p := exePath(pid)
	if len(o.paths) > 4096 {
		clear(o.paths)
	}
	o.paths[pid] = cached{p, time.Now()}
	return p
}

func exePath(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return ""
	}
	return strings.ToLower(windows.UTF16ToString(buf[:n]))
}
