package dhcphost

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"
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
