package dhcphost

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
)

func TestUnchanged(t *testing.T) {
	old := nmcli
	defer func() { nmcli = old }()
	nmcli = func(context.Context, ...string) (string, error) {
		return "u-up:activated\nu-new:activating\n", nil
	}
	for _, c := range []struct {
		p    Profile
		want bool
	}{
		{Profile{UUID: "u-up", Device: "wlan0", Activated: true}, true},
		{Profile{UUID: "u-off"}, true},
		{Profile{UUID: "u-new"}, false}, // listed inactive, connecting now
		{Profile{UUID: "u-off", Device: "eth0", Activated: true}, false},
		{Profile{UUID: "u-up", Device: "wlan0"}, false}, // deactivating when listed
	} {
		if got := unchanged(context.Background(), c.p); got != c.want {
			t.Errorf("%+v: %v, want %v", c.p, got, c.want)
		}
	}
}

func TestRetryReload(t *testing.T) {
	old, oldEvery := nmcli, reloadEvery
	defer func() { nmcli, reloadEvery = old, oldEvery }()
	reloadEvery = time.Millisecond
	calls := 0
	nmcli = func(context.Context, ...string) (string, error) {
		calls++
		if calls < 3 {
			return "", errors.New("NetworkManager is not running")
		}
		return "", nil
	}
	retryReload(slog.New(slog.DiscardHandler))
	if calls != 3 {
		t.Errorf("%d calls, want 3 (stop at the first success)", calls)
	}
}

func TestWriteDefaultsRetriesUntilDirectoryExists(t *testing.T) {
	oldN, oldEvery, oldFile := nmcli, reloadEvery, defaultsFile
	defer func() { nmcli, reloadEvery, defaultsFile = oldN, oldEvery, oldFile }()
	reloadEvery = 5 * time.Millisecond
	dir := t.TempDir()
	blocker := filepath.Join(dir, "nm") // a file where the directory belongs: mkdir fails
	if err := os.WriteFile(blocker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	defaultsFile = filepath.Join(blocker, "conf.d", "95-test.conf")
	var mu2 sync.Mutex
	reloads := 0
	nmcli = func(context.Context, ...string) (string, error) {
		mu2.Lock()
		defer mu2.Unlock()
		reloads++
		return "", nil
	}
	c := &config.Config{}
	c.Daemon.MAC = config.MACRandom
	writeDefaults(context.Background(), c, slog.New(slog.DiscardHandler))
	mu2.Lock()
	if reloads != 0 {
		t.Fatalf("reloaded %d times before the file could be written", reloads)
	}
	mu2.Unlock()
	if err := os.Remove(blocker); err != nil { // "NetworkManager" is up now
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for writeRetrying.Load() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	got, err := os.ReadFile(defaultsFile)
	if err != nil || string(got) != Defaults(c) {
		t.Fatalf("file after retry: %q, %v", got, err)
	}
	mu2.Lock()
	defer mu2.Unlock()
	if reloads != 1 {
		t.Errorf("%d reloads, want 1 after the write", reloads)
	}
	if !defaultsLive.Load() {
		t.Error("defaultsLive not set after the reload")
	}
}
