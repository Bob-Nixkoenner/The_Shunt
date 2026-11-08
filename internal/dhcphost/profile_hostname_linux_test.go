package dhcphost

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/godbus/dbus/v5"
)

// fakeNM answers nmcli for two cable profiles, both sending the host name
// (as NetworkManager 1.46 creates them), and records every modify/reapply.
type fakeNM struct {
	calls     []string
	failWrite bool // modify without --temporary fails (profile only in /run)
	active    string
}

func (f *fakeNM) run(_ context.Context, args ...string) (string, error) {
	line := strings.Join(args, " ")
	switch {
	case strings.HasPrefix(line, "-t -f UUID,TYPE,DEVICE,STATE"):
		return "u-new:802-3-ethernet:eth0:activated\nu-trust:802-3-ethernet:eth1:activated\n", nil
	case strings.HasPrefix(line, "-t -f UUID,STATE"):
		return "u-new:activated\nu-trust:activated\n", nil
	case strings.HasPrefix(line, "-g "):
		return "yes\nyes\n--\n--\n--\n--\n--\n", nil
	case strings.HasPrefix(line, "connection modify"):
		if f.failWrite && !strings.Contains(line, "--temporary") {
			return "", errors.New("cannot write")
		}
	}
	f.calls = append(f.calls, line)
	return "", nil
}

func setup(t *testing.T) *fakeNM {
	t.Helper()
	f := &fakeNM{}
	oldN, oldL, oldF := nmcli, lookPath, defaultsFile
	t.Cleanup(func() { nmcli, lookPath, defaultsFile = oldN, oldL, oldF })
	nmcli = f.run
	lookPath = func(string) (string, error) { return "nmcli", nil }
	defaultsFile = filepath.Join(t.TempDir(), "conf.d", "95.conf")
	return f
}

func hostnamePolicy(t *testing.T) Policy {
	c, err := config.Parse("[daemon]\ndhcp_hostname = \"none\"\n[[network]]\nname = \"home\"\ngateway_mac = [\"aa:bb:cc:dd:ee:ff\"]\ndefault_route = \"direct\"\ndhcp_hostname = \"send\"\n")
	if err != nil {
		t.Fatal(err)
	}
	c.Daemon.MAC = "" // the host name alone
	return Policy{Config: c}
}

func modified(f *fakeNM, uuid string) string {
	for _, c := range f.calls {
		if strings.HasPrefix(c, "connection modify") && strings.Contains(c, uuid) {
			return c
		}
	}
	return ""
}

func TestApplySetsHostnamePerProfile(t *testing.T) {
	f := setup(t)
	Apply(context.Background(), hostnamePolicy(t), slog.New(slog.DiscardHandler))
	for _, u := range []string{"u-new", "u-trust"} {
		m := modified(f, u)
		if !strings.Contains(m, "ipv4.dhcp-send-hostname no") || !strings.Contains(m, "ipv6.dhcp-send-hostname no") {
			t.Errorf("%s: %q", u, m)
		}
	}
}

func TestApplyTrustedNetworkKeepsHostname(t *testing.T) {
	f := setup(t)
	pol := hostnamePolicy(t)
	pol.Current = "home" // the profiles in use are on the "send" network
	Apply(context.Background(), pol, slog.New(slog.DiscardHandler))
	if m := modified(f, "u-new"); m != "" {
		t.Errorf("send network touched: %q", m)
	}
}

func TestApplyTemporaryFallback(t *testing.T) {
	f := setup(t)
	f.failWrite = true
	Apply(context.Background(), hostnamePolicy(t), slog.New(slog.DiscardHandler))
	if m := modified(f, "u-new"); !strings.Contains(m, "--temporary") {
		t.Errorf("no runtime-only change: %q", m)
	}
}

func TestSendNetworkRestoresHostname(t *testing.T) {
	// a profile that was set to "no" while the network was not known
	p := Profile{UUID: "u", Device: "eth0", Send4: "no", Send6: "no"}
	pol := hostnamePolicy(t)
	pol.Current = "home"
	now, _ := pol.Changes(p)
	if strings.Join(now, " ") != "ipv4.dhcp-send-hostname yes ipv6.dhcp-send-hostname yes" {
		t.Errorf("way back: %v", now)
	}
}

func TestNewConnectionSignalRunsAtOnce(t *testing.T) {
	old, oldA := newProfileWait, activatedWait
	defer func() { newProfileWait, activatedWait = old, oldA }()
	newProfileWait, activatedWait = 10*time.Millisecond, 10*time.Millisecond
	var n atomic.Int32
	f := func() { n.Add(1) }
	handleSignal(&dbus.Signal{Name: "org.freedesktop.NetworkManager.Settings.NewConnection"}, f)
	if n.Load() != 1 {
		t.Errorf("not set before the profile connects: %d calls", n.Load())
	}
	time.Sleep(60 * time.Millisecond)
	if n.Load() != 2 {
		t.Errorf("no second pass: %d calls", n.Load())
	}
	// a device that came up: one pass for several signals
	dev := &dbus.Signal{Name: "org.freedesktop.NetworkManager.Device.StateChanged", Body: []any{uint32(100)}}
	handleSignal(dev, f)
	handleSignal(dev, f)
	time.Sleep(60 * time.Millisecond)
	if n.Load() != 3 {
		t.Errorf("activated: %d calls, want 3", n.Load())
	}
}
