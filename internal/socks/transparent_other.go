//go:build !linux

package socks

import (
	"errors"
	"net"
	"net/netip"
)

func isClosed(err error) bool { return errors.Is(err, net.ErrClosed) }

func originalDst(net.Conn) (netip.AddrPort, error) {
	return netip.AddrPort{}, errors.New("transparent proxy needs Linux")
}
