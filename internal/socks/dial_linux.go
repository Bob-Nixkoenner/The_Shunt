package socks

import (
	"context"
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var errRefused = syscall.ECONNREFUSED

// MarkedDialer dials with SO_MARK: the connection takes the tunnel's routing
// table and, if the tunnel is down, fails instead of leaking.
func MarkedDialer(mark uint32) func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 8 * time.Second, Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark))
		}); err != nil {
			return err
		}
		return serr
	}}
	return d.DialContext
}
