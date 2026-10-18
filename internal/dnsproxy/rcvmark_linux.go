package dnsproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sys/unix"
)

// A redirect to the proxy (nft nat) is decided once per conntrack entry: a
// program that reuses the source port and destination of another route's UDP
// query within the entry's lifetime gets redirected to that route's listener.
// The packet itself still carries the mark of its own route, so the listener
// asks for it (SO_RCVMARK, Linux 6.1+) and answers for the route that mark
// stands for. Older kernels keep the old behaviour.

const soRcvMark = 75 // SO_RCVMARK

// markAddr is the sender's address plus the mark the query packet carried.
type markAddr struct {
	*net.UDPAddr
	mark uint32
}

// markConn is a UDP socket whose reads report the mark of every packet.
type markConn struct {
	*net.UDPConn
}

func (c *markConn) WriteTo(b []byte, a net.Addr) (int, error) {
	if m, ok := a.(markAddr); ok {
		a = m.UDPAddr
	}
	ua, ok := a.(*net.UDPAddr)
	if !ok {
		return 0, errors.New("dnsproxy: not a UDP address")
	}
	return c.UDPConn.WriteToUDP(b, ua)
}

// markReader reads UDP queries with their marks; TCP and plain UDP go through the default reader.
type markReader struct{ dns.Reader }

func (r markReader) ReadPacketConn(conn net.PacketConn, timeout time.Duration) ([]byte, net.Addr, error) {
	c, ok := conn.(*markConn)
	if !ok {
		return nil, nil, errors.New("dnsproxy: not a marked connection")
	}
	if timeout > 0 {
		_ = c.SetReadDeadline(time.Now().Add(timeout))
	}
	buf := make([]byte, dns.MaxMsgSize)
	oob := make([]byte, 128)
	n, oobn, _, from, err := c.ReadMsgUDP(buf, oob)
	if err != nil {
		return nil, nil, err
	}
	a := markAddr{UDPAddr: from} // no control message = mark 0 (the kernel only reports a mark that is set)
	if msgs, err := unix.ParseSocketControlMessage(oob[:oobn]); err == nil {
		for _, m := range msgs {
			if m.Header.Level == unix.SOL_SOCKET && m.Header.Type == unix.SO_MARK && len(m.Data) >= 4 {
				a.mark = binary.NativeEndian.Uint32(m.Data)
			}
		}
	}
	return buf[:n], a, nil
}

// markUnknown: the packet's mark could not be read.
const markUnknown = ^uint32(0)

// newUDPServer returns a UDP server that reports each query's mark through
// markOf, or nil when the kernel has no SO_RCVMARK.
func newUDPServer(addr string, h dns.Handler, started func()) *dns.Server {
	var set error
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) { set = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, soRcvMark, 1) })
	}}
	pc, err := lc.ListenPacket(context.Background(), "udp", addr)
	if err != nil {
		return nil
	}
	if set != nil {
		_ = pc.Close()
		return nil
	}
	return &dns.Server{PacketConn: &markConn{pc.(*net.UDPConn)}, Net: "udp", Handler: h, NotifyStartedFunc: started,
		DecorateReader: func(r dns.Reader) dns.Reader { return markReader{r} }}
}

// queryMark returns the mark of the query packet behind w (markUnknown if not known).
func queryMark(w dns.ResponseWriter) uint32 {
	if a, ok := w.RemoteAddr().(markAddr); ok {
		return a.mark
	}
	return markUnknown
}
