package dhcphost

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
)

const (
	nmBus      = "org.freedesktop.NetworkManager"
	nmPath     = dbus.ObjectPath("/org/freedesktop/NetworkManager")
	nmDevice   = nmBus + ".Device"
	nmSettings = nmBus + ".Settings"
)

// The start guard. A profile added and connected in one go (joining a
// Wi-Fi for the first time is NetworkManager's AddAndActivateConnection;
// in the lab nmcli connection add + up) starts before Apply can set it, and
// NetworkManager copies the profile into the device ("applied connection")
// when the activation begins: a change to the profile no longer reaches
// that first DHCP, which carries the host name (DHCP option 12, DHCPv6
// FQDN). NetworkManager 1.52+ ignores a global default for it.
//
// So while a device prepares the connection (states 40-60, DHCP starts at
// 70) the applied settings are read; if they would send the host name
// against the policy, the device is disconnected at once (one D-Bus call,
// before DHCP), the profile is set with nmcli (changing a profile that is
// connecting can stall NetworkManager's DHCP, seen with 1.54) and the
// connection is started again. A reapply would not help: DHCP has sent its
// first request by then. Each profile is restarted at most once per
// guardAgain, so a profile nmcli cannot change does not loop.

// guardAgain: how long a profile is not restarted again.
var guardAgain = 2 * time.Minute

var guarded struct {
	sync.Mutex
	at map[string]time.Time
}

// guardOnce reports whether uuid may be restarted now (and notes it).
func guardOnce(uuid string, now time.Time) bool {
	guarded.Lock()
	defer guarded.Unlock()
	if guarded.at == nil {
		guarded.at = map[string]time.Time{}
	}
	if t, ok := guarded.at[uuid]; ok && now.Sub(t) < guardAgain {
		return false
	}
	guarded.at[uuid] = now
	return true
}

// appliedOf reads NetworkManager settings (GetAppliedConnection,
// GetSettings). ok is false for anything but a Wi-Fi or cable profile.
func appliedOf(s map[string]map[string]dbus.Variant) (Applied, bool) {
	val := func(sec, key string) any {
		if v, ok := s[sec][key]; ok {
			return v.Value()
		}
		return nil
	}
	ip := func(sec string) map[string]any {
		m := map[string]any{}
		for k, v := range s[sec] {
			m[k] = v.Value()
		}
		return m
	}
	t, _ := val("connection", "type").(string)
	if t != "802-3-ethernet" && t != "802-11-wireless" {
		return Applied{}, false
	}
	a := Applied{Wifi: t == "802-11-wireless", Send4: sendsHostname(ip("ipv4")), Send6: sendsHostname(ip("ipv6"))}
	a.UUID, _ = val("connection", "uuid").(string)
	if b, ok := val("802-11-wireless", "ssid").([]byte); ok {
		a.SSID = string(b)
	}
	// an IP family switched off does not ask DHCP
	if m, _ := val("ipv4", "method").(string); m == "disabled" {
		a.Send4 = false
	}
	if m, _ := val("ipv6", "method").(string); m == "disabled" || m == "ignore" {
		a.Send6 = false
	}
	return a, a.UUID != ""
}

// guardDevice checks the connection a device is preparing (see above).
func guardDevice(ctx context.Context, conn *dbus.Conn, dev dbus.ObjectPath, polf func() (Policy, bool), log *slog.Logger) {
	pol, ok := polf()
	if !ok {
		return
	}
	obj := conn.Object(nmBus, dev)
	var s map[string]map[string]dbus.Variant
	var version uint64
	if err := obj.CallWithContext(ctx, nmDevice+".GetAppliedConnection", 0, uint32(0)).Store(&s, &version); err != nil {
		return // no connection on it (any more)
	}
	a, ok := appliedOf(s)
	if !ok || !pol.GuardNeeded(a) || !guardOnce(a.UUID, time.Now()) {
		return
	}
	if err := obj.CallWithContext(ctx, nmDevice+".Disconnect", 0).Err; err != nil {
		log.Warn("network privacy: cannot stop a connection that would send the host name", "uuid", a.UUID, "err", err)
		return
	}
	log.Info("network privacy: stopped a new connection before DHCP to switch off the host name", "uuid", a.UUID)
	go restartSet(ctx, conn, dev, a.UUID, log)
}

// restartSet sets the profile and connects it again on dev.
func restartSet(ctx context.Context, conn *dbus.Conn, dev dbus.ObjectPath, uuid string, log *slog.Logger) {
	if err := modify(ctx, uuid, []string{"ipv4.dhcp-send-hostname", "no", "ipv6.dhcp-send-hostname", "no"}); err != nil {
		// connect anyway: offline without a word is worse; the warning says why
		log.Warn("network privacy: cannot switch off the host name, connecting as it is", "uuid", uuid, "err", err)
	}
	var path dbus.ObjectPath
	if err := conn.Object(nmBus, nmPath+"/Settings").CallWithContext(ctx, nmSettings+".GetConnectionByUuid", 0, uuid).Store(&path); err != nil {
		log.Warn("network privacy: profile gone, not connecting again", "uuid", uuid, "err", err)
		return
	}
	var active dbus.ObjectPath
	if err := conn.Object(nmBus, nmPath).CallWithContext(ctx, nmBus+".ActivateConnection", 0, path, dev, dbus.ObjectPath("/")).Store(&active); err != nil {
		log.Warn("network privacy: cannot connect again", "uuid", uuid, "err", err)
		return
	}
	log.Info("network privacy: connecting again without the host name", "uuid", uuid)
}
