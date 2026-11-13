package splitstack

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Rests of a crashed run (OpenVPN config, torrc) are wiped, the folders of
// removed tunnels go, everything else stays.
func TestCleanWorkDir(t *testing.T) {
	work := t.TempDir()
	put := func(p string) {
		f := filepath.Join(work, p)
		os.MkdirAll(filepath.Dir(f), 0o700)
		if err := os.WriteFile(f, []byte("secret"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	put("openvpn/o/tunnel.ovpn")           // crash rest of a configured tunnel
	put("openvpn/gone/tunnel.ovpn")        // tunnel removed meanwhile
	put("tor/t/torrc")                     // crash rest
	put("tor/t/data/state")                // Tor's own state: stays
	put("tor/old/data/state")              // removed tunnel: folder goes
	put("tor/geoip")                       // GeoIP table next to the folders
	put("tailscale/gone/tailscaled.state") // not ours to tidy
	cfg, _ := json.Marshal(map[string]any{
		"tunnels": []map[string]string{
			{"name": "o", "type": "openvpn", "conf": "client\nremote 192.0.2.1\n"},
			{"name": "t", "type": "tor", "conf": "client = builtin\n"},
		},
		"default":  "direct",
		"work_dir": work,
	})
	if n := CleanWorkDir(string(cfg)); n != 5 {
		t.Errorf("cleaned %d, want 5", n)
	}
	for p, want := range map[string]bool{
		"openvpn/o/tunnel.ovpn":           false,
		"openvpn/o":                       true,
		"openvpn/gone":                    false,
		"tor/t/torrc":                     false,
		"tor/t/data/state":                true,
		"tor/old":                         false,
		"tor/geoip":                       true,
		"tailscale/gone/tailscaled.state": true,
	} {
		_, err := os.Stat(filepath.Join(work, p))
		if got := err == nil; got != want {
			t.Errorf("%s exists=%v, want %v", p, got, want)
		}
	}
	if CleanWorkDir(`{"default":"direct"}`) != 0 || CleanWorkDir("{") != 0 {
		t.Error("no work_dir / bad JSON")
	}
}
