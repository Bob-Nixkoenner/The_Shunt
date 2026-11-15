package defense

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
)

// AddrListen returns a ListenFunc that binds decoy ports to one local
// address: local() names it at that moment (Windows: the uplink's IPv4
// address, so the listener never sits on the tunnel adapter and its
// answers leave through the uplink). A port that taken reports as held
// by another program is skipped: a decoy must never sit in front of a
// real service. lc carries socket options (may be zero).
func AddrListen(local func() netip.Addr, taken func(port int) bool, lc net.ListenConfig) ListenFunc {
	return func(port int) (net.Listener, error) {
		if local == nil {
			return nil, errors.New("no uplink address")
		}
		a := local()
		if !a.IsValid() || a.IsUnspecified() {
			return nil, errors.New("no uplink address")
		}
		if taken != nil && taken(port) {
			return nil, fmt.Errorf("port %d is in use by another program", port)
		}
		network := "tcp4"
		if a.Is6() {
			network = "tcp6"
		}
		return lc.Listen(context.Background(), network, net.JoinHostPort(a.String(), strconv.Itoa(port)))
	}
}
