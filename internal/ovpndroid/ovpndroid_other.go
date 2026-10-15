//go:build !linux

package ovpndroid

import (
	"errors"
	"net/netip"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

// Options for Start (see ovpndroid.go; Android and Linux only).
type Options struct {
	Exe, Config, Dir, User, Pass string
	MTU                          int
	Protect                      func(fd int) bool
	Logf                         func(format string, args ...any)
}

// Tunnel is not available on this platform.
type Tunnel struct{}

// Start fails: OpenVPN behind the split stack needs Android (or Linux).
func Start(Options) (*Tunnel, error) {
	return nil, errors.New("OpenVPN tunnels are not supported on this platform")
}

func (t *Tunnel) Net() *netstack.Net     { return nil }
func (t *Tunnel) Addrs() []netip.Addr    { return nil }
func (t *Tunnel) DNS() []netip.Addr      { return nil }
func (t *Tunnel) Connected() bool        { return false }
func (t *Tunnel) Bytes() (rx, tx int64)  { return 0, 0 }
func (t *Tunnel) Pid() int               { return 0 }
func (t *Tunnel) Ready() <-chan struct{} { return nil }
func (t *Tunnel) Done() <-chan struct{}  { c := make(chan struct{}); close(c); return c }
func (t *Tunnel) Err() error             { return errors.New("not supported") }
func (t *Tunnel) Reconnect()             {}
func (t *Tunnel) NetworkChanged()        {}
func (t *Tunnel) Close()                 {}
