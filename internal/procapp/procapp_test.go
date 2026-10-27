//go:build linux

package procapp

import (
	"net"
	"net/netip"
	"os"
	"testing"
)

func TestOwnConnection(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	got := TCP(netip.MustParseAddrPort(c.LocalAddr().String()))
	exe, _ := os.ReadFile("/proc/self/comm")
	if want := string(exe[:len(exe)-1]); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
