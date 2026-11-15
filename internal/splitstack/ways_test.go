package splitstack

import (
	"net"
	"net/netip"
	"testing"
)

func TestCountWay(t *testing.T) {
	e := &Engine{}
	a, b := net.Pipe()
	defer b.Close()
	go func() { b.Write([]byte("hello")); buf := make([]byte, 3); b.Read(buf) }()
	c := e.countWay(a, netip.MustParseAddr("192.168.1.5"))
	buf := make([]byte, 5)
	c.Read(buf)
	c.Write([]byte("abc"))
	if e.wayLAN.rx.Load() != 5 || e.wayLAN.tx.Load() != 3 || e.wayDirect.rx.Load() != 0 {
		t.Fatal("lan count wrong")
	}
	if isLocalAddr(netip.MustParseAddr("8.8.8.8")) || !isLocalAddr(netip.MustParseAddr("fe80::1")) {
		t.Fatal("classification")
	}
}
