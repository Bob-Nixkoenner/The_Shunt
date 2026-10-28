package dhcphost

import (
	"os"
	"path/filepath"
	"testing"
)

func TestForgetLease(t *testing.T) {
	leaseDir = t.TempDir()
	for _, f := range []string{"internal-u1-wlan0.lease", "dhclient6-u1-eth0.lease", "internal-u2-wlan0.lease", "secret_key"} {
		if err := os.WriteFile(filepath.Join(leaseDir, f), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if n := forgetLease("u1"); n != 2 {
		t.Errorf("removed %d, want 2", n)
	}
	left, _ := filepath.Glob(filepath.Join(leaseDir, "*"))
	if len(left) != 2 {
		t.Errorf("left %v", left)
	}
}
