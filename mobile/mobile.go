//go:build linux

// Package mobile is The Shunt's core for Android (bound with gomobile).
//
// Android gives a VPN app exactly one TUN interface. To still route every
// app its own way - several WireGuard tunnels at the same time, direct, or
// blocked - the TUN goes to internal/splitstack, which re-makes every
// connection on the route of its app. The Shunt app itself is excluded from
// its own VPN, so the core's sockets go out directly.
//
// The Kotlin side owns the configuration and the UI; it calls Start with the
// TUN file descriptor and a JSON config, and answers UID lookups
// (ConnectivityManager.getConnectionOwnerUid). App IDs in the config are
// UIDs.
package mobile

import (
	"fmt"
	"net/netip"
	"strconv"

	"github.com/Bob-Nixkoenner/the_shunt/internal/splitstack"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
)

// Platform is implemented by the Android app.
type Platform interface {
	// OwnerUid returns the owner of a connection (proto 6 = TCP, 17 = UDP),
	// or -1 if unknown.
	OwnerUid(proto int, srcIP string, srcPort int, dstIP string, dstPort int) int
	Log(msg string)
}

// DNSAddr is the DNS server the VPN announces (VpnService.Builder
// .addDnsServer).
const DNSAddr = splitstack.DNSAddr

// Engine runs while the VPN is up.
type Engine struct{ e *splitstack.Engine }

// Start takes over the TUN file descriptor; the app closes it after Stop.
func Start(tunFD int, configJSON string, p Platform) (*Engine, error) {
	if err := unix.SetNonblock(tunFD, true); err != nil {
		return nil, fmt.Errorf("tun fd: %w", err)
	}
	mtu, err := splitstack.MTU(configJSON)
	if err != nil {
		return nil, err
	}
	ep, err := fdbased.New(&fdbased.Options{FDs: []int{tunFD}, MTU: uint32(mtu), PacketDispatchMode: fdbased.Readv})
	if err != nil {
		return nil, fmt.Errorf("tun endpoint: %v", err)
	}
	o := splitstack.Options{Link: ep}
	if p != nil {
		o.Log = p.Log
		o.Owner = func(proto int, src, dst netip.AddrPort) string {
			uid := p.OwnerUid(proto, src.Addr().String(), int(src.Port()), dst.Addr().String(), int(dst.Port()))
			if uid < 0 {
				return ""
			}
			return strconv.Itoa(uid)
		}
	}
	e, err := splitstack.New(o, configJSON)
	if err != nil {
		return nil, err
	}
	return &Engine{e}, nil
}

// SetRules swaps default route, app rules and DNS filter without restarting
// (same JSON format; tunnels in it are ignored, new connections only).
func (e *Engine) SetRules(configJSON string) error { return e.e.SetRules(configJSON) }

// Status returns the state as JSON.
func (e *Engine) Status() string { return e.e.Status() }

// Stop ends everything; the Engine cannot be started again.
func (e *Engine) Stop() { e.e.Stop() }

// CheckWireGuard validates a wg-quick file (import) and returns a short JSON
// summary: addresses, DNS, endpoints.
func CheckWireGuard(conf string) (string, error) { return splitstack.CheckWireGuard(conf) }
