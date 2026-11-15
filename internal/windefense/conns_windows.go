//go:build windows

package windefense

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procGetExtTCP = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetExtendedTcpTable")

const tcpTableOwnerPIDAll = 5 // TCP_TABLE_OWNER_PID_ALL

func extTable(family uint32) ([]byte, error) {
	size := uint32(32 << 10)
	for try := 0; try < 4; try++ {
		buf := make([]byte, size)
		r, _, _ := procGetExtTCP.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0,
			uintptr(family), tcpTableOwnerPIDAll, 0)
		switch syscall.Errno(r) {
		case 0:
			return buf[:size], nil
		case windows.ERROR_INSUFFICIENT_BUFFER:
			size += size / 4 // the table grew between the two calls
		default:
			return nil, syscall.Errno(r)
		}
	}
	return nil, windows.ERROR_INSUFFICIENT_BUFFER
}

// listConns reads the IPv4 and IPv6 TCP tables with the owning process.
var listConns = func() ([]TCPConn, error) {
	b4, err := extTable(windows.AF_INET)
	if err != nil {
		return nil, err
	}
	out := ParseTCP4(b4)
	if b6, err := extTable(windows.AF_INET6); err == nil {
		out = append(out, ParseTCP6(b6)...)
	}
	return out, nil
}

// processName is the image path of process pid ("" when it may not be read).
func processName(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, 1024)
	n := uint32(len(buf))
	if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}
