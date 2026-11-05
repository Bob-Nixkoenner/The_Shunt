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
