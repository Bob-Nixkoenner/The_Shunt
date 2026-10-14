package winsplit

import (
	"context"
	"encoding/binary"
	"net"
	"syscall"

	"golang.org/x/sys/windows"
)

// IP_UNICAST_IF / IPV6_UNICAST_IF (ws2ipdef.h): send through this
// interface whatever the routing table says - the way out of our own TUN,
// whose routes cover everything.
const unicastIF = 31

// BindToInterface returns a net.Dialer Control function that pins sockets
// to the interface index ifIndex() (the physical network, looked up at dial
// time so it follows Wi-Fi/Ethernet changes).
func BindToInterface(ifIndex func() uint32) func(network, address string, c syscall.RawConn) error {
	return func(network, _ string, c syscall.RawConn) error {
		idx := ifIndex()
		var serr error
		err := c.Control(func(fd uintptr) {
			h := windows.Handle(fd)
			if network == "tcp6" || network == "udp6" {
				serr = windows.SetsockoptInt(h, windows.IPPROTO_IPV6, unicastIF, int(idx))
				return
			}
			// IPv4 wants the index in network byte order
			var be [4]byte
			binary.BigEndian.PutUint32(be[:], idx)
			serr = windows.SetsockoptInt(h, windows.IPPROTO_IP, unicastIF, int(binary.LittleEndian.Uint32(be[:])))
		})
		if err != nil {
			return err
		}
		return serr
	}
}

// DialDirect fits splitstack.Options.DialDirect.
func DialDirect(ifIndex func() uint32) func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := net.Dialer{Control: BindToInterface(ifIndex)}
	return d.DialContext
}
