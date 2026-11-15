//go:build windows

package defense

import (
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/sys/windows"
)

// soExclusiveAddrUse is SO_EXCLUSIVEADDRUSE (~SO_REUSEADDR): nobody can
// bind the same address and port next to the decoy (and take its
// connections).
const soExclusiveAddrUse = ^int(windows.SO_REUSEADDR)

// WindowsListen returns the ListenFunc of the Windows service: TCP on the
// uplink's address (local), exclusive, ports held by other programs
// skipped (taken). Ports below 1024 need no extra right on Windows.
func WindowsListen(local func() netip.Addr, taken func(port int) bool) ListenFunc {
	return AddrListen(local, taken, net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, soExclusiveAddrUse, 1)
		}); err != nil {
			return err
		}
		return serr
	}})
}
