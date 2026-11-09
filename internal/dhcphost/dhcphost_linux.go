package dhcphost

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/godbus/dbus/v5"
)

// nmcli, not a D-Bus Update: Update replaces the whole profile and may
// drop the Wi-Fi password, nmcli changes single properties.
var nmcli = func(ctx context.Context, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "nmcli", args...).Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return "", fmt.Errorf("nmcli %s: %w: %s", args[0], err, strings.TrimSpace(string(ee.Stderr)))
		}
		return "", err
	}
	return string(out), nil
}

var lookPath = exec.LookPath

var mu sync.Mutex // one pass at a time (start, network change, new profile)

// randomUUIDs: profiles with a new MAC on every connection, as of the last
// pass; their leases are forgotten whenever a device disconnects.
var (
	randomMu    sync.Mutex
	randomUUIDs []string
)

// defaultsFile: NetworkManager reads /run/NetworkManager/conf.d as well;
// a file there is gone after a reboot, before shuntd has looked at the
// config again.
var defaultsFile = "/run/NetworkManager/conf.d/95-shunt-network-privacy.conf"

// defaultsLive: NetworkManager has read defaultsFile as it is now; only
// then a connection in use may already run with its values (Covered).
var defaultsLive atomic.Bool

// leaseDir: where NetworkManager keeps the last DHCP lease per profile.
var leaseDir = "/var/lib/NetworkManager"

// forgetLease removes the DHCP leases NetworkManager kept for a profile.
// With a new MAC on every connection the old lease would give it away: the
// next connection asks for the address it had (DHCP option 50), which
// links the new MAC to the old one, and waits for it in vain.
func forgetLease(uuid string) (removed int) {
	for _, pat := range []string{"internal-" + uuid + "-*.lease", "internal6-" + uuid + "-*.lease", "dhclient-" + uuid + "-*.lease", "dhclient6-" + uuid + "-*.lease"} {
		fs, _ := filepath.Glob(filepath.Join(leaseDir, pat))
		for _, f := range fs {
			if os.Remove(f) == nil {
				removed++
			}
		}
	}
	return removed
}

// writeDefaults puts Defaults in place (or removes them) and has
// NetworkManager read its configuration again if that changed anything.
func writeDefaults(ctx context.Context, c *config.Config, log *slog.Logger) {
	want := Defaults(c)
	have, _ := os.ReadFile(defaultsFile)
	if string(have) == want {
		return // read already (or retryReload still at it)
	}
	defaultsLive.Store(false)
	var err error
	if want == "" {
		err = os.Remove(defaultsFile)
	} else if err = os.MkdirAll(filepath.Dir(defaultsFile), 0o755); err == nil {
		err = os.WriteFile(defaultsFile, []byte(want), 0o644)
	}
	if err != nil && !os.IsNotExist(err) {
		log.Warn("network privacy: cannot write NetworkManager defaults, trying again", "err", err)
		retryWrite(ctx, c, log)
		return
	}
	_, err = nmcli(ctx, "general", "reload", "conf")
	defaultsLive.Store(err == nil && want != "")
	if err != nil {
		// at boot shuntd starts next to NetworkManager: it may have read
		// its configuration already and not answer yet; the file is in
		// place, so later passes would not try again
		log.Warn("network privacy: NetworkManager did not reload its configuration, trying again", "err", err)
		go retryReload(log)
	}
}

// writeRetrying: one retryWrite at a time.
var writeRetrying atomic.Bool

// retryWrite tries writeDefaults again every few seconds until the file is
// in place (and NetworkManager reloaded): the directory may not exist yet at
// boot, because shuntd starts before NetworkManager.
func retryWrite(ctx context.Context, c *config.Config, log *slog.Logger) {
	if !writeRetrying.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer writeRetrying.Store(false)
		for i := 0; i < reloadRetries; i++ {
			time.Sleep(reloadEvery)
			if ctx.Err() != nil {
				return
			}
			mu.Lock()
			want := Defaults(c)
			err := tryWrite(want)
			if err == nil {
				// reload NetworkManager so connections already up get the defaults
				_, err = nmcli(ctx, "general", "reload", "conf")
				defaultsLive.Store(err == nil && want != "")
				if err != nil {
					log.Warn("network privacy: NetworkManager did not reload its configuration, trying again", "err", err)
					go retryReload(log)
				} else {
					log.Info("network privacy: NetworkManager defaults written")
				}
				mu.Unlock()
				return
			}
			mu.Unlock()
		}
		log.Warn("network privacy: NetworkManager defaults could not be written; restart shuntd once NetworkManager runs")
	}()
}

// tryWrite puts want in defaultsFile (removes it when empty).
func tryWrite(want string) error {
	var err error
	if want == "" {
		err = os.Remove(defaultsFile)
	} else if err = os.MkdirAll(filepath.Dir(defaultsFile), 0o755); err == nil {
		err = os.WriteFile(defaultsFile, []byte(want), 0o644)
	}
	if os.IsNotExist(err) && want == "" {
		return nil
	}
	return err
}

// reloadRetries, reloadEvery: how long retryReload keeps trying.
var (
	reloadRetries = 30
	reloadEvery   = 2 * time.Second
)

func retryReload(log *slog.Logger) {
	for i := 0; i < reloadRetries; i++ {
		time.Sleep(reloadEvery)
		if _, err := nmcli(context.Background(), "general", "reload", "conf"); err == nil {
			defaultsLive.Store(true)
			log.Info("network privacy: NetworkManager read the defaults")
			return
		}
	}
	log.Warn("network privacy: NetworkManager never read the defaults; new networks get them only after the next change")
}

// modify changes single properties of a profile. A profile that lives
// only in /run (netplan) or a file that cannot be written takes the change
// for the running NetworkManager only.
func modify(ctx context.Context, uuid string, props []string) error {
	_, err := nmcli(ctx, append([]string{"connection", "modify", uuid}, props...)...)
	if err != nil {
		_, err2 := nmcli(ctx, append([]string{"connection", "modify", "--temporary", uuid}, props...)...)
		if err2 == nil {
			return nil
		}
	}
	return err
}

// Apply writes the defaults for new profiles and sets every Wi-Fi and
// cable profile as pol wants it. A profile in
// use gets the change at once (reapply: the address is renewed), except a
// new MAC: that one waits for the next connection rather than cut the
// current one.
func Apply(ctx context.Context, pol Policy, log *slog.Logger) {
	if _, err := lookPath("nmcli"); err != nil {
		return // no NetworkManager
	}
	mu.Lock()
	defer mu.Unlock()
	writeDefaults(ctx, pol.Config, log) // also removes them when switched off
	if pol.Config.Daemon.DHCPHostname == "" && pol.Config.Daemon.MAC == "" {
		return
	}
	ps, err := list(ctx)
	if err != nil {
		log.Warn("dhcp host name: cannot read the NetworkManager profiles", "err", err)
		return
	}
	var random []string
	for _, p := range ps {
		if pol.MACMode(p) == config.MACRandom {
			random = append(random, p.UUID)
		}
	}
	randomMu.Lock()
	randomUUIDs = random
	randomMu.Unlock()
	for _, p := range ps {
		if p.Device == "" && pol.MACMode(p) == config.MACRandom {
			if n := forgetLease(p.UUID); n > 0 {
				log.Info("network privacy: forgot the last DHCP lease", "uuid", p.UUID)
			}
		}
		if p.Connecting {
			continue
		}
		now, next := pol.Changes(p)
		if len(now)+len(next) > 0 && !unchanged(ctx, p) {
			continue // the next pass, after the connection, sets it
		}
		// reapply before the MAC is in the profile: a changed MAC cannot
		// be reapplied and would fail the whole reapply
		if len(now) > 0 {
			if err := modify(ctx, p.UUID, now); err != nil {
				log.Warn("network privacy: cannot change profile", "uuid", p.UUID, "err", err)
				continue
			}
			log.Info("network privacy", "uuid", p.UUID, "set", strings.Join(now, " "))
			if p.Device != "" && p.Activated && !(defaultsLive.Load() && pol.Covered(p, now)) {
				if _, err := nmcli(ctx, "device", "reapply", p.Device); err != nil {
					log.Warn("network privacy: applies from the next connection", "device", p.Device, "err", err)
				}
			}
		}
		if len(next) > 0 {
			if err := modify(ctx, p.UUID, next); err != nil {
				log.Warn("network privacy: cannot change the MAC", "uuid", p.UUID, "err", err)
				continue
			}
			log.Info("network privacy: MAC from the next connection", "uuid", p.UUID, "set", strings.Join(next, " "), "in_use", p.Device != "")
		}
	}
}

// unchanged tells whether p is still in the state list saw. Listing all
// profiles takes a moment, and a profile that started to connect since
// must not be changed: NetworkManager then never finishes its DHCP (seen
// with NM 1.54 for any property, a new profile connected at once).
func unchanged(ctx context.Context, p Profile) bool {
	out, err := nmcli(ctx, "-t", "-f", "UUID,STATE", "connection", "show", "--active")
	if err != nil {
		return false
	}
	state := ""
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if f := splitTerse(l); len(f) == 2 && f[0] == p.UUID {
			state = f[1]
		}
	}
	switch {
	case p.Activated:
		return state == "activated"
	case p.Device == "":
		return state == ""
	}
	return false // deactivating: wait for the next pass
}

func list(ctx context.Context) ([]Profile, error) {
	out, err := nmcli(ctx, "-t", "-f", "UUID,TYPE,DEVICE,STATE", "connection", "show")
	if err != nil {
		return nil, err
	}
	var ps []Profile
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		f := splitTerse(l)
		if len(f) < 3 || (f[1] != "802-11-wireless" && f[1] != "802-3-ethernet") {
			continue
		}
		p := Profile{UUID: f[0], Wifi: f[1] == "802-11-wireless", Device: f[2]}
		p.Activated = len(f) > 3 && f[3] == "activated"
		p.Connecting = len(f) > 3 && f[3] == "activating"
		macProp := "802-3-ethernet.cloned-mac-address"
		if p.Wifi {
			macProp = "802-11-wireless.cloned-mac-address"
		}
		fields := "ipv4.dhcp-send-hostname,ipv6.dhcp-send-hostname," + macProp + ",ipv6.dhcp-duid,ipv4.dhcp-client-id,ipv6.addr-gen-mode,ipv6.ip6-privacy"
		if p.Wifi {
			fields += ",802-11-wireless.ssid" // last: a name may contain newlines
		}
		v, err := nmcli(ctx, "-g", fields, "connection", "show", p.UUID)
		if err != nil {
			return nil, err
		}
		vs := strings.Split(strings.TrimRight(v, "\n"), "\n")
		if len(vs) < 7 {
			continue
		}
		p.Send4, p.Send6, p.MAC, p.DUID, p.ClientID, p.AddrGen, p.Privacy = vs[0], vs[1], unescape(vs[2]), vs[3], vs[4], vs[5], vs[6]
		if p.Wifi && len(vs) > 7 {
			p.SSID = unescape(strings.Join(vs[7:], "\n"))
		}
		ps = append(ps, p)
	}
	return ps, nil
}

// splitTerse splits an nmcli -t line at unescaped colons.
func splitTerse(l string) []string {
	var out []string
	var b strings.Builder
	for i := 0; i < len(l); i++ {
		switch {
		case l[i] == '\\' && i+1 < len(l):
			i++
			b.WriteByte(l[i])
		case l[i] == ':':
			out = append(out, b.String())
			b.Reset()
		default:
			b.WriteByte(l[i])
		}
	}
	return append(out, b.String())
}

func unescape(s string) string {
	return strings.NewReplacer(`\:`, ":", `\\`, `\`).Replace(s)
}

// newProfileWait: how long WatchNew waits after a new profile.
var newProfileWait = 2 * time.Second

// WatchNew calls f when NetworkManager adds a profile (a Wi-Fi joined for
// the first time), so it is set before it connects the next time, and if
// it is connecting already, reapplied. When a device disconnects or fails
// to connect, the leases of the profiles with mac = "random" are forgotten
// at once, before the next connection could ask for the old address.
//
// pol (may be nil) gives the current policy for the start guard: a
// connection that starts with a profile that would send the host name
// against the policy is stopped before its DHCP, set, and started again
// (guardDevice).
func WatchNew(ctx context.Context, f func(), pol func() (Policy, bool), log *slog.Logger) error {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.AddMatchSignal(
		dbus.WithMatchInterface("org.freedesktop.NetworkManager.Settings"),
		dbus.WithMatchMember("NewConnection"),
	); err != nil {
		return err
	}
	if err := conn.AddMatchSignal(
		dbus.WithMatchInterface("org.freedesktop.NetworkManager.Device"),
		dbus.WithMatchMember("StateChanged"),
	); err != nil {
		return err
	}
	ch := make(chan *dbus.Signal, 8)
	conn.Signal(ch)
	for {
		select {
		case <-ctx.Done():
			return nil
		case s, ok := <-ch:
			if !ok {
				return errors.New("system bus closed")
			}
			// first, before anything slower: the window before DHCP is short
			if pol != nil && s.Name == nmDevice+".StateChanged" && len(s.Body) > 0 {
				if st, ok := s.Body[0].(uint32); ok && guardState(st) {
					guardDevice(ctx, conn, s.Path, pol, log)
				}
			}
			handleSignal(s, f)
		}
	}
}

// activatedWait: how long after a device is up before the profiles are
// looked at again (one pass for several signals).
var activatedWait = 3 * time.Second

var activatedTimer struct {
	sync.Mutex
	t *time.Timer
}

// handleSignal reacts to one NetworkManager signal.
func handleSignal(s *dbus.Signal, f func()) {
	if s.Name != "org.freedesktop.NetworkManager.Device.StateChanged" {
		// a profile added: set it at once, before it connects (a profile
		// that connects first would send the host name in its first DHCP
		// request; NetworkManager 1.46 has no default for that). Again
		// after a moment: a profile added and connected at once (nmcli
		// connection add + up, joining a Wi-Fi) is left alone by the first
		// pass while it connects.
		f()
		time.AfterFunc(newProfileWait, f)
		return
	}
	if len(s.Body) == 0 {
		return
	}
	st, ok := s.Body[0].(uint32)
	if !ok {
		return
	}
	switch st {
	case 30, 120: // NM_DEVICE_STATE_DISCONNECTED, _FAILED
		randomMu.Lock()
		for _, u := range randomUUIDs {
			forgetLease(u)
		}
		randomMu.Unlock()
	case 100: // NM_DEVICE_STATE_ACTIVATED: a profile skipped while it connected
		activatedTimer.Lock()
		if activatedTimer.t != nil {
			activatedTimer.t.Stop()
		}
		activatedTimer.t = time.AfterFunc(activatedWait, f)
		activatedTimer.Unlock()
	}
}
