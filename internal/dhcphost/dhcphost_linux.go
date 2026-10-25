package dhcphost

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"sync"
	"time"

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

var mu sync.Mutex // one pass at a time (start, network change, new profile)

// Apply sets every Wi-Fi and cable profile as pol wants it. A profile in
// use gets the change at once (reapply: the address is renewed).
func Apply(ctx context.Context, pol Policy, log *slog.Logger) {
	if pol.Config.Daemon.DHCPHostname == "" {
		return
	}
	if _, err := exec.LookPath("nmcli"); err != nil {
		return // no NetworkManager
	}
	mu.Lock()
	defer mu.Unlock()
	ps, err := list(ctx)
	if err != nil {
		log.Warn("dhcp host name: cannot read the NetworkManager profiles", "err", err)
		return
	}
	for _, p := range ps {
		v := pol.Change(p)
		if v == "" {
			continue
		}
		if _, err := nmcli(ctx, "connection", "modify", p.UUID, "ipv4.dhcp-send-hostname", v, "ipv6.dhcp-send-hostname", v); err != nil {
			log.Warn("dhcp host name: cannot change profile", "uuid", p.UUID, "err", err)
			continue
		}
		log.Info("dhcp host name", "uuid", p.UUID, "send", v)
		if p.Device != "" {
			if _, err := nmcli(ctx, "device", "reapply", p.Device); err != nil {
				log.Warn("dhcp host name: applies from the next connection", "device", p.Device, "err", err)
			}
		}
	}
}

func list(ctx context.Context) ([]Profile, error) {
	out, err := nmcli(ctx, "-t", "-f", "UUID,TYPE,DEVICE", "connection", "show")
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
		fields := "ipv4.dhcp-send-hostname,ipv6.dhcp-send-hostname"
		if p.Wifi {
			fields += ",802-11-wireless.ssid"
		}
		v, err := nmcli(ctx, "-g", fields, "connection", "show", p.UUID)
		if err != nil {
			return nil, err
		}
		vs := strings.Split(strings.TrimRight(v, "\n"), "\n")
		if len(vs) < 2 {
			continue
		}
		p.Send4, p.Send6 = vs[0], vs[1]
		if p.Wifi && len(vs) > 2 {
			p.SSID = unescape(strings.Join(vs[2:], "\n"))
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

// WatchNew calls f when NetworkManager adds a profile (a Wi-Fi joined for
// the first time), so it is set before it connects the next time, and if
// it is connecting already, reapplied.
func WatchNew(ctx context.Context, f func()) error {
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
	ch := make(chan *dbus.Signal, 8)
	conn.Signal(ch)
	for {
		select {
		case <-ctx.Done():
			return nil
		case _, ok := <-ch:
			if !ok {
				return errors.New("system bus closed")
			}
			f()
		}
	}
}
