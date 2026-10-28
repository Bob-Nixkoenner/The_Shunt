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
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/splitstack"
	"github.com/Bob-Nixkoenner/the_shunt/internal/update"
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

// History returns the traffic and DNS-block history as JSON for a range
// ("1h", "24h", "7d" or "30d"): points of traffic and blocked names, per-tunnel
// series, and the blocks of today and this month.
func (e *Engine) History(rng string) string { return e.e.History(rng) }

// NetworkChanged is called by the app when the default network changes.
func (e *Engine) NetworkChanged() { e.e.NetworkChanged() }

// SetTimezone sets the zone for times in the log (an IANA name such as
// "Europe/Berlin", from java.util.TimeZone.getDefault().id): Go has no TZ
// variable in an Android app and would print UTC.
func SetTimezone(name string) error {
	loc, err := time.LoadLocation(name)
	if err != nil {
		return err
	}
	time.Local = loc
	return nil
}

// SetNetwork reports the network (link: "wifi", "mobile", "ethernet" or "";
// ssid: Wi-Fi name, "" if unknown) and returns the name of the matching
// network profile ("" = none). Call it on every network change, after
// NetworkChanged.
func (e *Engine) SetNetwork(link, ssid string) string { return e.e.SetNetwork(link, ssid) }

// SetPanic blocks everything at once, running connections included.
func (e *Engine) SetPanic(on bool) { e.e.SetPanic(on) }

// Pass lets everything through for minutes (1..60; 0 ends it) and returns
// the end as unix seconds (0: ended). Connections opened because of it are
// cut when it ends.
func (e *Engine) Pass(minutes int) int64 {
	until := e.e.Pass(time.Duration(minutes) * time.Minute)
	if until.IsZero() {
		return 0
	}
	return until.Unix()
}

// LeakTest checks every route (public IP, DNS resolver; contacts
// api.ipify.org and Google DNS through each route) and returns JSON.
// Blocks for up to ~10 s: call it off the main thread.
func (e *Engine) LeakTest() string {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return e.e.LeakTest(ctx)
}

// ResetStats deletes the traffic totals.
func (e *Engine) ResetStats() error { return e.e.ResetStats() }

// Stop ends everything; the Engine cannot be started again.
func (e *Engine) Stop() { e.e.Stop() }

// CheckWireGuard validates a wg-quick file (import) and returns a short JSON
// summary: addresses, DNS, endpoints.
func CheckWireGuard(conf string) (string, error) { return splitstack.CheckWireGuard(conf) }

// CheckOpenVPN validates a .ovpn file for import: JSON with "remotes",
// "needs_auth", "removed" (lines taken out: scripts, management, …) and
// "clean" (the text to store).
func CheckOpenVPN(conf string) (string, error) { return splitstack.CheckOpenVPN(conf) }

// CheckTor validates the file of a Tor tunnel: JSON with "socks" and "dns".
func CheckTor(conf string) (string, error) { return splitstack.CheckTor(conf) }

// VerifyUpdate checks the release signature of a downloaded SHA256SUMS file
// (error if it was not signed by the release key) and returns the SHA-256
// (hex) that the file lists for name, "" if it lists none.
func VerifyUpdate(sums, sig, name string) (string, error) {
	if err := update.VerifySums([]byte(sums), []byte(sig)); err != nil {
		return "", err
	}
	h, _ := update.SumFor([]byte(sums), name)
	return h, nil
}
