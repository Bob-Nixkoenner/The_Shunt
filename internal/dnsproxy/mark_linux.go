package dnsproxy

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// markControl sets SO_MARK so the query takes the route's routing table:
// a tunnel's upstream is only reachable through that tunnel, and if the
// tunnel is down the query fails instead of leaking.
func markControl(mark uint32) func(string, string, syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark))
		})
		if err != nil {
			return err
		}
		return serr
	}
}
