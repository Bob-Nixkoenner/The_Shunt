//go:build linux

package tunnel

import (
	"io"
	"log/slog"
	"testing"
	"time"
)

// A connection whose TUN interface has no way to see counters (interface
// missing) is left alone and the watcher ends at once.
func TestWatchStallNoInterface(t *testing.T) {
	o := &OpenVPN{
		spec: OpenVPNSpec{Name: "t", Iface: "shunt-nonexist0"},
		log:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		stop: make(chan struct{}),
	}
	done := make(chan struct{})
	go func() { o.watchStall(1, 1); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("watchStall did not end")
	}
}
