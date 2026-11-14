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
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/splitstack"
	"github.com/Bob-Nixkoenner/the_shunt/internal/update"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
)

// Platform is implemented by the Android app.
type Platform interface {
	// OwnerUid returns the owner of a connection (proto 6 = TCP, 17 = UDP),
	// -1 if unknown, -2 if the lookup failed with an error. A negative
	// answer is asked again up to twice (see ownerLookup).
	OwnerUid(proto int, srcIP string, srcPort int, dstIP string, dstPort int) int
	Log(msg string)
	// AppName returns the package name for a UID (first package that uses
	// it), "" if unknown. Called only from the defense worker, never from
	// the packet path.
	AppName(uid int) string
}

// DNSAddr is the DNS server the VPN announces (VpnService.Builder
// .addDnsServer).
const DNSAddr = splitstack.DNSAddr

// Engine runs while the VPN is up.
type Engine struct {
	e    *splitstack.Engine
	def  *defenseState
	conf string // the start config: its work_dir is tidied after Stop
}

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
	var ds *defenseState
	{
		var c struct {
			DefenseDir string `json:"defense_dir"`
		}
		_ = json.Unmarshal([]byte(configJSON), &c)
		var obs *defObs
		ds, obs = newDefense(c.DefenseDir, p)
		o.Observer = obs
	}
	if p != nil {
		o.Log = p.Log
		o.Owner = (&ownerLookup{p: p, pause: ownerPause, log: p.Log}).owner
	}
	// rests of a crashed run (OpenVPN config, torrc with keys/bridges) and
	// folders of removed tunnels; the app starts one engine at a time
	if n := splitstack.CleanWorkDir(configJSON); n > 0 && o.Log != nil {
		o.Log(fmt.Sprintf("work folder: removed %d leftovers", n))
	}
	e, err := splitstack.New(o, configJSON)
	if err != nil {
		ds.m.Close()
		splitstack.CleanWorkDir(configJSON)
		return nil, err
	}
	return &Engine{e: e, def: ds, conf: configJSON}, nil
}

// SetRules swaps default route, app rules and DNS filter without restarting
// (same JSON format; tunnels in it are ignored, new connections only).
func (e *Engine) SetRules(configJSON string) error { return e.e.SetRules(configJSON) }

// Status returns the state as JSON.
func (e *Engine) Status() string {
	s := e.e.Status()
	// "defense": see defense.go (spliced in, the core's JSON stays as it is)
	if n := len(s); n > 1 && s[n-1] == '}' {
		return s[:n-1] + `,"defense":` + e.defenseJSON() + "}"
	}
	return s
}

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
// Blocks for up to ~10 s, a Tor that is still starting up to ~2 minutes:
// call it off the main thread.
func (e *Engine) LeakTest() string {
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	return e.e.LeakTest(ctx)
}

// TorNewIdentity gives the built-in Tor of the tunnel new circuits; "" = done, else the reason.
func (e *Engine) TorNewIdentity(name string) string { return e.e.TorNewIdentity(name) }

// TorExit makes one probe through the tunnel (public IP; for Tor also
// check.torproject.org, as the leak test) and returns its JSON, "" on error.
// After TorNewIdentity it makes tor build the new circuit, so the status
// shows the new exit. Blocks up to ~30 s: call it off the main thread.
func (e *Engine) TorExit(name string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	b, err := e.e.ProbeRoute(ctx, "tunnel:"+name)
	if err != nil {
		return ""
	}
	return string(b)
}

// TorStart makes the built-in Tor of the tunnel start now; "" = done, else the reason.
func (e *Engine) TorStart(name string) string { return e.e.TorStart(name) }

// ResetStats deletes the traffic totals.
func (e *Engine) ResetStats() error { return e.e.ResetStats() }

// Stop ends everything; the Engine cannot be started again.
func (e *Engine) Stop() {
	e.e.Stop()
	e.def.m.Close()
	splitstack.CleanWorkDir(e.conf) // openvpn/tor have ended: nothing of theirs with keys stays
}

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

// Owner lookups: Android's getConnectionOwnerUid can miss a connection that
// is only just being set up. A miss is asked again; a connection whose owner
// stays unknown gets the default route, or is dropped with owner_unknown
// "drop" (Max Security), see splitstack.Owner.
const (
	ownerTries    = 3 // 1 + 2 retries: at most ~2*ownerPause extra per connection
	ownerPause    = 20 * time.Millisecond
	ownerErr      = -2 // OwnerUid: the lookup threw
	ownerLogEvery = time.Minute
)

// ownerLookup asks the platform for the owner of a connection, with
// retries. It runs on the connection's own goroutine (splitstack calls Owner
// there, not on the TUN reader), so the pauses hold up only that connection.
// Misses are logged as counts at most once per ownerLogEvery: no app,
// address or port.
type ownerLookup struct {
	p     Platform
	pause time.Duration
	log   func(string)

	mu                         sync.Mutex
	last                       time.Time // last log line
	unknown, errs, nouid, late int       // since then
}

func (l *ownerLookup) owner(proto int, src, dst netip.AddrPort) string {
	s, d := src.Addr().String(), dst.Addr().String()
	errs, nouid := 0, 0
	for i := 0; i < ownerTries; i++ {
		if i > 0 {
			time.Sleep(l.pause)
		}
		uid := l.p.OwnerUid(proto, s, int(src.Port()), d, int(dst.Port()))
		if uid >= 0 {
			if i > 0 {
				l.note(false, errs, nouid)
			}
			return strconv.Itoa(uid)
		}
		if uid == ownerErr {
			errs++
		} else {
			nouid++
		}
	}
	l.note(true, errs, nouid)
	return ""
}

// note counts misses of one connection (unknown: none of the tries found
// the owner) and logs the counts when the last line is old enough.
func (l *ownerLookup) note(unknown bool, errs, nouid int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if unknown {
		l.unknown++
	} else {
		l.late++
	}
	l.errs += errs
	l.nouid += nouid
	now := time.Now()
	if l.log == nil || now.Sub(l.last) < ownerLogEvery {
		return
	}
	l.last = now
	l.log(fmt.Sprintf("owner lookup: %d connections without owner, %d found on a retry (misses: %d errors, %d unknown)",
		l.unknown, l.late, l.errs, l.nouid))
	l.unknown, l.late, l.errs, l.nouid = 0, 0, 0, 0
}
