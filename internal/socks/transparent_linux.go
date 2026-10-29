package socks

import (
	"errors"
	"net"
	"net/netip"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func isClosed(err error) bool { return errors.Is(err, net.ErrClosed) }

const soOriginalDst = 80 // SO_ORIGINAL_DST, IP6T_SO_ORIGINAL_DST

// originalDst returns where the redirected connection was going.
func originalDst(c net.Conn) (netip.AddrPort, error) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return netip.AddrPort{}, errors.New("not a TCP connection")
	}
	rc, err := tc.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, err
	}
	var dst netip.AddrPort
	var serr error
	err = rc.Control(func(fd uintptr) {
		var buf [28]byte
		size := uint32(len(buf))
		level := unix.SOL_IP
		if la, ok := c.LocalAddr().(*net.TCPAddr); ok && la.IP.To4() == nil {
			level = unix.SOL_IPV6
		}
		_, _, e := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, uintptr(level), soOriginalDst,
			uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0)
		if e != 0 {
			serr = e
			return
		}
		port := uint16(buf[2])<<8 | uint16(buf[3])
		switch buf[0] { // sa_family (host order, little endian on every Linux we run on)
		case unix.AF_INET:
			dst = netip.AddrPortFrom(netip.AddrFrom4([4]byte(buf[4:8])), port)
		case unix.AF_INET6:
			dst = netip.AddrPortFrom(netip.AddrFrom16([16]byte(buf[8:24])), port)
		default:
			serr = errors.New("unknown address family")
		}
	})
	if err != nil {
		return netip.AddrPort{}, err
	}
	if serr != nil {
		return netip.AddrPort{}, serr
	}
	// a connection made straight to the proxy port (not redirected)
	if la, ok := c.LocalAddr().(*net.TCPAddr); ok && dst.Port() == uint16(la.Port) && la.IP.IsLoopback() && dst.Addr().IsLoopback() {
		return netip.AddrPort{}, errors.New("not redirected")
	}
	return dst, nil
}
