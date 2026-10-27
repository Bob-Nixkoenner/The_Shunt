//go:build !linux

package socks

import (
	"context"
	"errors"
	"net"
)

var errRefused = errors.New("connection refused")

// MarkedDialer: packet marks exist on Linux only.
func MarkedDialer(uint32) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("socks exit needs the Linux kernel route")
	}
}
