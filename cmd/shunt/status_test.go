package main

import (
	"testing"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/tunnel"
)

func TestHasHandshake(t *testing.T) {
	if hasHandshake(nil) || hasHandshake([]tunnel.PeerStatus{{}}) {
		t.Fatal("no peer or a zero handshake time is not connected")
	}
	if !hasHandshake([]tunnel.PeerStatus{{}, {LastHandshake: time.Now()}}) {
		t.Fatal("a peer with a handshake time is connected")
	}
}

func TestNoHandshake(t *testing.T) {
	never := []tunnel.PeerStatus{{}}
	done := []tunnel.PeerStatus{{LastHandshake: time.Now()}}
	if !noHandshake("kernel", never) || !noHandshake("userspace", nil) {
		t.Fatal("wireguard without handshake must be flagged")
	}
	if noHandshake("kernel", done) {
		t.Fatal("handshake done")
	}
	for _, d := range []string{"openvpn", "tailscale", "tor"} {
		if noHandshake(d, never) {
			t.Fatalf("%s has no wireguard handshake", d)
		}
	}
}
