package splitstack

import (
	"net"
	"testing"
	"time"
)

// A one-way UDP stream (the app only receives) must not be cut after the
// idle time of the silent direction; a fully idle flow must end.
func TestRelayUDPOneWay(t *testing.T) {
	appIn, appSide := net.Pipe()  // app <-> relay
	srvOut, srvSide := net.Pipe() // relay <-> server
	idle := 200 * time.Millisecond
	ended := make(chan struct{})
	go func() { relayUDP(appSide, srvSide, idle); close(ended) }()

	got := make(chan int, 100)
	go func() {
		buf := make([]byte, 16)
		for {
			if _, err := appIn.Read(buf); err != nil {
				close(got)
				return
			}
			got <- 1
		}
	}()
	for i := 0; i < 10; i++ { // 10 × 60 ms = 3 idle periods, server -> app only
		if _, err := srvOut.Write([]byte("x")); err != nil {
			t.Fatalf("write %d: relay closed a busy flow: %v", i, err)
		}
		time.Sleep(60 * time.Millisecond)
	}
	n := 0
	for len(got) > 0 {
		n += <-got
	}
	if n != 10 {
		t.Errorf("app got %d of 10 datagrams", n)
	}
	select { // now silent both ways: the flow ends
	case <-ended:
	case <-time.After(5 * idle):
		t.Fatal("idle flow was not closed")
	}
}
