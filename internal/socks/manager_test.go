package socks

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"
)

// M-04 (external report): an exit address another program holds is reported
// and not counted as running, so the daemon can block it; a free one is
// bound and served by us.
func TestManagerReportsTakenAddress(t *testing.T) {
	squat, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no loopback:", err)
	}
	defer squat.Close()
	taken := squat.Addr().String()

	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	freeAddr := free.Addr().String()
	free.Close()

	m := &Manager{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	defer m.Close()
	dial := func(context.Context, string, string) (net.Conn, error) { return nil, net.ErrClosed }
	got := m.Update(map[string]Exit{
		"squatted": {Listen: taken, Dial: dial},
		"ours":     {Listen: freeAddr, Dial: dial},
	})
	want := netip.MustParseAddrPort(taken)
	if len(got) != 1 || got[0] != want {
		t.Fatalf("taken = %v, want [%v]", got, want)
	}
	addrs := m.Addrs()
	if _, ok := addrs["squatted"]; ok {
		t.Fatal("a taken address must not count as a running exit")
	}
	if addrs["ours"] != freeAddr {
		t.Fatalf("free exit not running: %v", addrs)
	}
	// once the other program is gone the next update binds it
	squat.Close()
	if got := m.Update(map[string]Exit{"squatted": {Listen: taken, Dial: dial}}); len(got) != 0 {
		t.Fatalf("freed address still reported: %v", got)
	}
	if m.Addrs()["squatted"] != taken {
		t.Fatal("freed address not bound")
	}
}
