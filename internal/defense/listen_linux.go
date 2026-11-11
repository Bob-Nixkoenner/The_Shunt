package defense

import (
	"context"
	"net"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// LinuxListen returns a ListenFunc for decoy ports: the listening socket
// carries mark (so answers take the main routing table, the physical link,
// never a tunnel) and is bound to the physical interface iface() names at
// that moment ("" = any interface, e.g. for tests). Ports below 1024 need
// CAP_NET_BIND_SERVICE; without it the port is skipped by the caller.
func LinuxListen(iface func() string, mark uint32) ListenFunc {
	return func(port int) (net.Listener, error) {
		dev := ""
		if iface != nil {
			dev = iface()
		}
		lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
			var serr error
			err := c.Control(func(fd uintptr) {
				if mark != 0 {
					if serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark)); serr != nil {
						return
					}
				}
				if dev != "" {
					serr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, dev)
				}
			})
			if err != nil {
				return err
			}
			return serr
		}}
		return lc.Listen(context.Background(), "tcp", net.JoinHostPort("", strconv.Itoa(port)))
	}
}
