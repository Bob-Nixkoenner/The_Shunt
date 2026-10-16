//go:build android

package splitstack

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"
)

// Tailscale tunnels are not built into the Android library (yet).

const typeTailscale = "tailscale"

var tsDNS = netip.MustParseAddr("100.100.100.100")

type tsTunnel struct{}

func startTailscale(string, string, string, func(string, ...any)) (*tsTunnel, error) {
	return nil, errors.New("Tailscale tunnels are not available on Android yet")
}

func (*tsTunnel) dial(context.Context, string, netip.AddrPort) (net.Conn, error) {
	return nil, errors.New("tailscale tunnel not available")
}

func (*tsTunnel) status() (bool, int64, int64, time.Time, string) {
	return false, 0, 0, time.Time{}, ""
}

func (*tsTunnel) close() {}
