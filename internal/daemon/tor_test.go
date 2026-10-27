package daemon

import (
	"strings"
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/Bob-Nixkoenner/the_shunt/internal/tunnel"
)

func TestNewIdentityErrors(t *testing.T) {
	d := &Daemon{cfg: &config.Config{Tunnels: map[string]config.Tunnel{
		"wg":  {Config: "a.conf"},
		"tor": {Driver: "tor"},
	}}, tunnels: map[string]tunnel.Device{}}
	if err := d.newIdentity("wg"); err == nil || !strings.Contains(err.Error(), "not a Tor tunnel") {
		t.Errorf("wireguard tunnel: %v", err)
	}
	if err := d.newIdentity("nope"); err == nil {
		t.Error("unknown tunnel accepted")
	}
	if err := d.newIdentity("tor"); err == nil || !strings.Contains(err.Error(), "not running") {
		t.Errorf("stopped tor: %v", err)
	}
}
