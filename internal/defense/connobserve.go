package defense

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Connection observation (Linux daemon polls the socket list and calls
// NoteConn): beaconing (regular new connections of one app to one
// destination) and first contact (an app talks to a destination it never
// used). Both are shown only; neither blocks anything.

const (
	beaconMinEvents = 8
	beaconThreshold = 0.8
	beaconCooldown  = time.Hour
	beaconMaxFired  = 1024

	// firstSeenLearn: an app's first minutes are learning only, no events.
	firstSeenLearn  = 10 * time.Minute
	maxFirstApps    = 200
	maxFirstTargets = 500
	// firstSeenBurst events per firstSeenPer; more are learned silently
	// and counted into the next event.
	firstSeenBurst = 6
	firstSeenPer   = time.Minute
)

// beaconExemptApps are system services that talk at fixed intervals on
// purpose (time sync, DHCP renewal, name resolution, package checks and the
// Shunt's own updater and list downloads). Lower case.
var beaconExemptApps = map[string]bool{
	"systemd-timesyncd": true, "chronyd": true, "ntpd": true, "ntpsec": true,
	"networkmanager": true, "systemd-resolved": true, "systemd-resolve": true,
	"dhclient": true, "dhcpcd": true, "avahi-daemon": true, "packagekitd": true,
	"fwupd": true, "snapd": true, "shuntd": true, "shunt": true, "the-shunt": true,
}

// beaconExemptPorts: NTP, DNS, DHCP/DHCPv6 (clients renew at fixed intervals).
var beaconExemptPorts = map[uint16]bool{53: true, 67: true, 68: true, 123: true, 546: true, 547: true}

// connState is the Manager's memory for NoteConn.
type connState struct {
	mu     sync.Mutex
	beacon *BeaconTracker
	fired  map[string]time.Time

	// first contact
	fsPath  string
	fsApps  map[string]*knownApp
	fsDirty bool
	fsLoad  bool
	burst   []time.Time
	dropped int
}

type knownApp struct {
	Since   time.Time `json:"since"`
	Targets []string  `json:"targets"` // hashed, oldest first
}

// WithFirstSeenFile keeps the known destinations per app in this file (mode
// 0600). Without it they stay in memory.
func WithFirstSeenFile(path string) Option { return func(m *Manager) { m.conn.fsPath = path } }

// appUsable: names that tell nothing about the program are not tracked for
// first contact.
func appUsable(app string) bool {
	return app != "" && app != "unknown" && app != "login session" && !strings.HasPrefix(app, "uid-")
}

// destTarget is how a destination is remembered: the base domain the proxy
// answered it for, else the /24 (IPv4) or /48 (IPv6). ok=false: not tracked
// (loopback, multicast, private and link-local ranges).
func (m *Manager) destTarget(a netip.Addr) (string, bool) {
	a = a.Unmap()
	if !a.IsValid() || a.IsLoopback() || a.IsUnspecified() || a.IsMulticast() ||
		a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() {
		return "", false
	}
	if d := m.domainOf(a); d != "" {
		return d, true
	}
	bits := 24
	if a.Is6() {
		bits = 48
	}
	p, _ := a.Prefix(bits)
	return p.String(), true
}

func targetHash(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:8])
}

// NoteConn reports one outgoing TCP connection of app to dst. fresh is
// false for connections that already existed when watching began (they
// count for first contact, not for beacons). app "" = owner unknown.
func (m *Manager) NoteConn(app string, dst netip.AddrPort, fresh bool) {
	if fs := m.feature(FeatFirstSeen); fs.Watch {
		m.noteFirstSeen(app, dst)
	}
	if fresh && m.feature(FeatBeacon).Watch {
		m.noteBeacon(app, dst)
	}
}

func (m *Manager) noteBeacon(app string, dst netip.AddrPort) {
	a := dst.Addr().Unmap()
	if beaconExemptApps[strings.ToLower(app)] || beaconExemptPorts[dst.Port()] ||
		a.IsLoopback() || a.IsUnspecified() || a.IsMulticast() || m.never.Contains(a) {
		return
	}
	if app == "" {
		app = "unknown"
	}
	now := m.now()
	key := app + "|" + netip.AddrPortFrom(a, dst.Port()).String()
	m.conn.mu.Lock()
	if m.conn.beacon == nil {
		m.conn.beacon = NewBeaconTracker()
	}
	if m.conn.fired == nil {
		m.conn.fired = map[string]time.Time{}
	}
	score, iv := m.conn.beacon.Add(key, now, beaconMinEvents)
	fire := false
	if score >= beaconThreshold {
		if t, ok := m.conn.fired[key]; !ok || now.Sub(t) >= beaconCooldown {
			if len(m.conn.fired) >= beaconMaxFired {
				for k, t := range m.conn.fired {
					if now.Sub(t) >= beaconCooldown {
						delete(m.conn.fired, k)
					}
				}
			}
			if len(m.conn.fired) < beaconMaxFired {
				m.conn.fired[key] = now
				fire = true
			}
		}
	}
	m.conn.mu.Unlock()
	if fire {
		m.Report(Event{Kind: KindBeacon, Severity: SevLow, Src: a.String(), Port: int(dst.Port()), Proto: "tcp",
			Detail: fmt.Sprintf("app=%s interval=%s score=%.2f", app, iv.Round(time.Second), score)})
	}
}

// ownApps are the Shunt's own programs (daemon, helpers, desktop app). Their
// destinations (list downloads, updater) are no news to the user.
var ownApps = map[string]bool{
	"shuntd": true, "shunt": true, "the-shunt": true, "shunt-desktop": true,
	"shuntd-win": true, "shunt-helper": true, "shunt-tray": true,
}

// OwnApp reports whether app (a socket owner name) is one of The Shunt's
// own programs.
func OwnApp(app string) bool { return ownApps[strings.ToLower(app)] }

func (m *Manager) noteFirstSeen(app string, dst netip.AddrPort) {
	if !appUsable(app) || ownApps[strings.ToLower(app)] {
		return
	}
	target, ok := m.destTarget(dst.Addr())
	if !ok {
		return
	}
	now := m.now()
	h := targetHash(target)
	m.conn.mu.Lock()
	m.loadFirstLocked()
	ka := m.conn.fsApps[app]
	if ka == nil {
		if len(m.conn.fsApps) >= maxFirstApps {
			m.conn.mu.Unlock()
			return
		}
		ka = &knownApp{Since: now}
		m.conn.fsApps[app] = ka
		m.conn.fsDirty = true
	}
	for _, t := range ka.Targets {
		if t == h {
			m.conn.mu.Unlock()
			return
		}
	}
	ka.Targets = append(ka.Targets, h)
	if len(ka.Targets) > maxFirstTargets {
		ka.Targets = ka.Targets[len(ka.Targets)-maxFirstTargets:]
	}
	m.conn.fsDirty = true
	if now.Sub(ka.Since) < firstSeenLearn {
		m.conn.mu.Unlock()
		return
	}
	keep := m.conn.burst[:0]
	for _, t := range m.conn.burst {
		if now.Sub(t) < firstSeenPer {
			keep = append(keep, t)
		}
	}
	m.conn.burst = keep
	if len(keep) >= firstSeenBurst {
		m.conn.dropped++
		m.conn.mu.Unlock()
		return
	}
	m.conn.burst = append(m.conn.burst, now)
	dropped := m.conn.dropped
	m.conn.dropped = 0
	m.conn.mu.Unlock()
	detail := "app=" + app + " target=" + target
	if dropped > 0 {
		detail += fmt.Sprintf(" more=%d", dropped)
	}
	m.Report(Event{Kind: KindFirstSeen, Severity: SevInfo, Src: dst.Addr().Unmap().String(), Port: int(dst.Port()), Proto: "tcp", Detail: detail})
}

// loadFirstLocked reads the file once. Caller holds conn.mu.
func (m *Manager) loadFirstLocked() {
	if m.conn.fsLoad {
		return
	}
	m.conn.fsLoad = true
	m.conn.fsApps = map[string]*knownApp{}
	if m.conn.fsPath == "" {
		return
	}
	b, err := os.ReadFile(m.conn.fsPath)
	if err != nil {
		return
	}
	var in map[string]*knownApp
	if json.Unmarshal(b, &in) == nil {
		for k, v := range in {
			if v != nil && len(m.conn.fsApps) < maxFirstApps {
				m.conn.fsApps[k] = v
			}
		}
	}
}

// flushFirstSeen writes the known destinations (0600) when they changed.
func (m *Manager) flushFirstSeen() error {
	m.conn.mu.Lock()
	if !m.conn.fsDirty || m.conn.fsPath == "" {
		m.conn.mu.Unlock()
		return nil
	}
	b, err := json.Marshal(m.conn.fsApps)
	m.conn.fsDirty = false
	path := m.conn.fsPath
	m.conn.mu.Unlock()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// forgetConns drops the beacon timestamps (new network).
func (m *Manager) forgetConns() {
	m.conn.mu.Lock()
	if m.conn.beacon != nil {
		m.conn.beacon.Forget()
	}
	m.conn.fired = nil
	m.conn.mu.Unlock()
}
