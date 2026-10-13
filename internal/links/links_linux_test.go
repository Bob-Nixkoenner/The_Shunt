package links

import (
	"os"
	"path/filepath"
	"testing"
)

func TestKind(t *testing.T) {
	sys := t.TempDir()
	mk := func(name string, files map[string]string) {
		for f, c := range files {
			p := filepath.Join(sys, name, f)
			_ = os.MkdirAll(filepath.Dir(p), 0o755)
			if c == "<dir>" {
				_ = os.MkdirAll(p, 0o755)
			} else {
				_ = os.WriteFile(p, []byte(c), 0o644)
			}
		}
	}
	mk("wlp60s0", map[string]string{"wireless": "<dir>", "device": "<dir>", "type": "1\n", "uevent": "DEVTYPE=wlan\n"})
	mk("eno1", map[string]string{"device": "<dir>", "type": "1\n", "uevent": "INTERFACE=eno1\n"})
	mk("wwan0", map[string]string{"device": "<dir>", "type": "65534\n", "uevent": "DEVTYPE=wwan\n"})
	mk("docker0", map[string]string{"type": "1\n", "uevent": "DEVTYPE=bridge\n"})
	mk("br0", map[string]string{"device": "<dir>", "type": "1\n", "uevent": "DEVTYPE=bridge\n"})
	for name, want := range map[string]string{"wlp60s0": "wifi", "eno1": "ethernet", "wwan0": "mobile", "docker0": "", "br0": ""} {
		if got := Kind(sys, name); got != want {
			t.Errorf("%s: %q, want %q", name, got, want)
		}
	}
}
