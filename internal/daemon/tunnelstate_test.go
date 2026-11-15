package daemon

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/netdetect"
)

const stateConf = "[daemon]\nsocket = \"/nonexistent/s.sock\"\n[dns]\ndisabled = true\n[tunnel.vpn]\nconfig = \"vpn.conf\"\n[[rule]]\nname = \"app\"\nport = [\"tcp/22\"]\nroute = \"tunnel:vpn\"\n"

func stateDaemon(t *testing.T) *Daemon {
	t.Helper()
	d, _ := testDaemon(t, stateConf)
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	wg := "[Interface]\nPrivateKey = " + key + "\nAddress = 10.9.0.2/32\n[Peer]\nPublicKey = " + key + "\nEndpoint = 192.0.2.1:51820\nAllowedIPs = 0.0.0.0/0\n"
	if err := os.WriteFile(filepath.Join(filepath.Dir(d.ConfigPath), "vpn.conf"), []byte(wg), 0o600); err != nil {
		t.Fatal(err)
	}
	return d
}

// Off or asleep: rules on the tunnel keep pointing at it (blocked), never
// at the direct route.
func TestSleepingTunnelNeverLeaks(t *testing.T) {
	d := stateDaemon(t)
	for _, sleep := range []bool{false, true} {
		p, err := PrepareOn(d.ConfigPath, "shunt", Env{Net: &netdetect.Info{}, Backend: newFake(), Sleep: map[string]bool{"vpn": sleep}})
		if err != nil {
			t.Fatal(err)
		}
		if got := p.Config.Tunnels["vpn"].Disabled; got != sleep {
			t.Fatalf("sleep=%v: disabled=%v", sleep, got)
		}
		for _, r := range p.Plan.Rules {
			if r.Name == "app" && r.Route.String() != "tunnel:vpn" {
				t.Errorf("sleep=%v: rule route %s, want tunnel:vpn", sleep, r.Route)
			}
		}
	}
}

func TestSetTunnelState(t *testing.T) {
	d := stateDaemon(t)
	if err := d.reload("shunt"); err != nil {
		t.Fatal(err)
	}
	file := func() string { b, _ := os.ReadFile(d.ConfigPath); return string(b) }
	if err := d.setTunnelState("nope", "off", 0); err == nil {
		t.Error("unknown tunnel accepted")
	}
	// sleeping: memory only, file untouched, comes back by itself
	if err := d.setTunnelState("vpn", "sleep", 30*time.Second); err == nil {
		t.Error("too short sleep accepted")
	}
	if err := d.setTunnelState("vpn", "sleep", time.Hour); err != nil {
		t.Fatal(err)
	}
	if strings.Count(file(), "disabled = true") > 1 || d.sleepLeft("vpn") == 0 {
		t.Fatal("sleep wrote the file or is not set")
	}
	if st := d.status(); !st.Tunnels[0].Disabled || st.Tunnels[0].SleepLeft == 0 || len(d.tunnels) != 0 {
		t.Fatalf("status while asleep: %+v", st.Tunnels)
	}
	// a file edit meanwhile does not make the sleep permanent
	if err := d.setTunnelState("vpn", "on", 0); err != nil {
		t.Fatal(err)
	}
	if d.sleepLeft("vpn") != 0 || d.status().Tunnels[0].Disabled {
		t.Fatal("on did not wake the tunnel")
	}
	// off: lasting, in the file
	if err := d.setTunnelState("vpn", "off", 0); err != nil {
		t.Fatal(err)
	}
	if strings.Count(file(), "disabled = true") < 2 || !d.status().Tunnels[0].Disabled {
		t.Fatal("off not saved")
	}
	if err := d.setTunnelState("vpn", "sleep", time.Hour); err == nil {
		t.Error("sleep of an off tunnel accepted")
	}
	if err := d.setTunnelState("vpn", "on", 0); err != nil {
		t.Fatal(err)
	}
	if strings.Count(file(), "disabled = true") > 1 {
		t.Fatal("on not saved")
	}
}

// Saving other edits while a tunnel sleeps must not write it as disabled.
func TestSleepNotPersistedByOtherSaves(t *testing.T) {
	d := stateDaemon(t)
	if err := d.reload("shunt"); err != nil {
		t.Fatal(err)
	}
	if err := d.setTunnelState("vpn", "sleep", time.Hour); err != nil {
		t.Fatal(err)
	}
	cfg := d.fileCfg()
	if cfg.Tunnels["vpn"].Disabled {
		t.Fatal("fileCfg carries the sleep")
	}
	d.stopSleep("vpn")
}
