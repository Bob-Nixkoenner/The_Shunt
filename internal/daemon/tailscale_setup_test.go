package daemon

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// The packaged file and the text shuntd writes must not drift apart.
func TestTailscaleDropInMatchesPackage(t *testing.T) {
	b, err := os.ReadFile("../../packaging/systemd/shuntd-tailscale.conf")
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != TailscaleDropIn {
		t.Error("packaging/systemd/shuntd-tailscale.conf differs from daemon.TailscaleDropIn")
	}
	// the base unit's RestrictNamespaces=yes must be reset before net is allowed
	if !strings.Contains(TailscaleDropIn, "RestrictNamespaces=\nRestrictNamespaces=net\n") {
		t.Error("drop-in must reset RestrictNamespaces, then allow net only")
	}
	for _, need := range []string{"CAP_SYS_ADMIN", "CAP_NET_RAW", "AF_PACKET", "[Service]"} {
		if !strings.Contains(TailscaleDropIn, need) {
			t.Errorf("drop-in lacks %s", need)
		}
	}
}

func TestSetupTailscale(t *testing.T) {
	dir := t.TempDir()
	oldPath, oldCtl := TailscaleDropInPath, systemctl
	t.Cleanup(func() { TailscaleDropInPath, systemctl = oldPath, oldCtl })
	TailscaleDropInPath = filepath.Join(dir, "shuntd.service.d", "50-tailscale.conf")
	var calls []string
	systemctl = func(args ...string) error { calls = append(calls, strings.Join(args, " ")); return nil }

	changed, err := SetupTailscale(false)
	if err != nil || !changed {
		t.Fatalf("install: changed=%v err=%v", changed, err)
	}
	if b, _ := os.ReadFile(TailscaleDropInPath); string(b) != TailscaleDropIn {
		t.Error("drop-in not written")
	}
	if strings.Join(calls, ";") != "daemon-reload;try-restart shuntd.service" {
		t.Errorf("systemctl calls %v", calls)
	}
	calls = nil
	if changed, err := SetupTailscale(false); err != nil || changed || len(calls) != 0 {
		t.Errorf("second install must do nothing: changed=%v err=%v calls=%v", changed, err, calls)
	}
	if changed, err := SetupTailscale(true); err != nil || !changed {
		t.Fatalf("remove: changed=%v err=%v", changed, err)
	}
	if _, err := os.Stat(TailscaleDropInPath); !errors.Is(err, os.ErrNotExist) {
		t.Error("drop-in not removed")
	}
	calls = nil
	if changed, err := SetupTailscale(true); err != nil || changed || len(calls) != 0 {
		t.Errorf("second remove must do nothing: changed=%v err=%v calls=%v", changed, err, calls)
	}
}

func TestTailscaleNeedsSetup(t *testing.T) {
	for _, c := range []struct {
		err  error
		want bool
	}{
		{fmt.Errorf("network namespace: %w", syscall.EPERM), true},
		{fmt.Errorf("veth: %w", syscall.EPERM), false},
		{fmt.Errorf("network namespace: %w", syscall.ENOMEM), false},
		{errors.New("tailscaled is not installed"), false},
		{nil, false},
	} {
		if got := tailscaleNeedsSetup(c.err); got != c.want {
			t.Errorf("%v: got %v, want %v", c.err, got, c.want)
		}
	}
}
