package splitstack

import (
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/stats"
)

// wayCount counts bytes of traffic that does not go through a tunnel.
type wayCount struct{ rx, tx atomic.Int64 }

// wayConn counts what passes through a direct connection.
type wayConn struct {
	net.Conn
	w *wayCount
}

func (c *wayConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.w.rx.Add(int64(n))
	return n, err
}

func (c *wayConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.w.tx.Add(int64(n))
	return n, err
}

// CloseWrite passes the half-close through, so relayTCP does not drop the
// connection before the reply has arrived.
func (c *wayConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

// isLocalAddr: the destination is on this machine or the local network.
func isLocalAddr(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsMulticast() || a.IsUnspecified()
}

// countWay wraps a direct connection: LAN destinations count as "lan", the
// rest as "direct".
func (e *Engine) countWay(c net.Conn, dst netip.Addr) net.Conn {
	w := &e.wayDirect
	if isLocalAddr(dst) {
		w = &e.wayLAN
	}
	return &wayConn{Conn: c, w: w}
}

// observeWays feeds the direct/LAN counters to the traffic book.
func (e *Engine) observeWays(now time.Time) {
	e.book.Observe(stats.WayDirect, e.wayDirect.rx.Load(), e.wayDirect.tx.Load(), now)
	e.book.Observe(stats.WayLAN, e.wayLAN.rx.Load(), e.wayLAN.tx.Load(), now)
}
