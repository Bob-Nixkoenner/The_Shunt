package dhcphost

import (
	"context"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
)

// macNM is NetworkManager with one cable profile in use: its cloned MAC as
// stored in the profile and the address the device runs with right now.
type macNM struct {
	profileMAC string // "random", "permanent"
	deviceMAC  string
	ups        int
	modifies   []string
}

func (f *macNM) run(_ context.Context, args ...string) (string, error) {
	line := strings.Join(args, " ")
	switch {
	case strings.HasPrefix(line, "-t -f UUID,TYPE,DEVICE,STATE"):
		return "u-lan:802-3-ethernet:eth0:activated\n", nil
	case strings.HasPrefix(line, "-t -f UUID,STATE"):
		return "u-lan:activated\n", nil
	case strings.HasPrefix(line, "-g GENERAL.HWADDR"):
		// the permanent hardware address, whatever the device runs with:
		// reconnectReal must not trust it (lab finding)
		return `00\:11\:22\:33\:44\:55` + "\n", nil
	case strings.HasPrefix(line, "-g "):
		// send4, send6, MAC, DUID, client ID, addr-gen, privacy
		return "no\nno\n" + f.profileMAC + "\nstable-uuid\nmac\nstable-privacy\n2\n", nil
	case strings.HasPrefix(line, "connection modify"):
		f.modifies = append(f.modifies, line)
		for _, m := range []string{"random", "permanent"} {
			if strings.HasSuffix(line, "cloned-mac-address "+m) || strings.Contains(line, "cloned-mac-address "+m+" ") {
				f.profileMAC = m
			}
		}
	case strings.HasPrefix(line, "-w 10 connection up uuid u-lan ifname eth0"):
		f.ups++
		if f.profileMAC == "permanent" {
			f.deviceMAC = "00:11:22:33:44:55" // the real one (universal)
		}
	}
	return "", nil
}

func macSetup(t *testing.T, f *macNM) {
	t.Helper()
	oldN, oldL, oldF, oldD := nmcli, lookPath, defaultsFile, deviceMAC
	t.Cleanup(func() {
		nmcli, lookPath, defaultsFile, deviceMAC = oldN, oldL, oldF, oldD
		reconnected.Lock()
		reconnected.at = nil
		reconnected.Unlock()
	})
	nmcli = f.run
	deviceMAC = func(string) (string, error) { return f.deviceMAC, nil }
	lookPath = func(string) (string, error) { return "nmcli", nil }
	defaultsFile = filepath.Join(t.TempDir(), "conf.d", "95.conf")
}

// macPolicy: random everywhere, the real MAC on the network found by its
// gateway MAC (current = "home" once it is recognised).
func macPolicy(t *testing.T, current string) Policy {
	t.Helper()
	c, err := config.Parse("[daemon]\nmac = \"random\"\ndhcp_hostname = \"none\"\n[[network]]\nname = \"home\"\ngateway_mac = [\"aa:bb:cc:dd:ee:ff\"]\ndefault_route = \"direct\"\nmac = \"permanent\"\n")
	if err != nil {
		t.Fatal(err)
	}
	return Policy{Config: c, Current: current}
}

func TestTrustedNetworkReconnectsOnceWithRealMAC(t *testing.T) {
	f := &macNM{profileMAC: "random", deviceMAC: "a2:00:00:00:00:01"}
	macSetup(t, f)
	log := slog.New(slog.DiscardHandler)
	// connected with a random MAC, then the gateway MAC says "home"
	Apply(context.Background(), macPolicy(t, "home"), log)
	if f.profileMAC != "permanent" || f.ups != 1 {
		t.Fatalf("profile %q, reconnects %d; want permanent, 1", f.profileMAC, f.ups)
	}
	// the pass after the new connection: real MAC on the device, nothing more
	Apply(context.Background(), macPolicy(t, "home"), log)
	if f.ups != 1 {
		t.Fatalf("reconnected again: %d", f.ups)
	}
}

func TestUnknownNetworkKeepsRandomMAC(t *testing.T) {
	f := &macNM{profileMAC: "random", deviceMAC: "a2:00:00:00:00:01"}
	macSetup(t, f)
	Apply(context.Background(), macPolicy(t, ""), slog.New(slog.DiscardHandler))
	if f.profileMAC != "random" || f.ups != 0 {
		t.Fatalf("profile %q, reconnects %d; want random, 0", f.profileMAC, f.ups)
	}
}

func TestTrustedNetworkReconnectDoesNotLoop(t *testing.T) {
	// NetworkManager keeps the random address (driver, failed activation):
	// the profile is not connected again and again
	f := &macNM{profileMAC: "random", deviceMAC: "a2:00:00:00:00:01"}
	macSetup(t, f)
	log := slog.New(slog.DiscardHandler)
	run := f.run
	nmcli = func(ctx context.Context, args ...string) (string, error) {
		out, err := run(ctx, args...)
		f.deviceMAC = "a2:00:00:00:00:01"
		return out, err
	}
	for i := 0; i < 3; i++ {
		Apply(context.Background(), macPolicy(t, ""), log)     // network not recognised (yet)
		Apply(context.Background(), macPolicy(t, "home"), log) // and recognised again
	}
	if f.ups != 1 {
		t.Fatalf("reconnects %d, want 1", f.ups)
	}
}

func TestReconnectOnceAgainLater(t *testing.T) {
	t.Cleanup(func() { reconnected.Lock(); reconnected.at = nil; reconnected.Unlock() })
	now := time.Now()
	if !reconnectOnce("u", now) || reconnectOnce("u", now.Add(time.Second)) || !reconnectOnce("u", now.Add(guardAgain+time.Second)) {
		t.Fatal("reconnectOnce")
	}
}

func TestLocalMAC(t *testing.T) {
	for mac, want := range map[string]bool{"a2:00:00:00:00:01": true, "02:aa:bb:cc:dd:ee": true, "00:11:22:33:44:55": false, "3c:00:00:00:00:00": false, "": true, "--": true} {
		if got := localMAC(mac); got != want {
			t.Errorf("localMAC(%q) = %v", mac, got)
		}
	}
}
