package defense

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

// Decoys bind the given local address only, skip ports another program
// holds and refuse to listen without an address.
func TestAddrListen(t *testing.T) {
	ports := freePortsAny(t, 2)
	lo := netip.MustParseAddr("127.0.0.1")
	held := ports[1]
	f := AddrListen(func() netip.Addr { return lo }, func(p int) bool { return p == held }, net.ListenConfig{})
	ln, err := f(ports[0])
	if err != nil {
		t.Skip("no loopback:", err)
	}
	defer ln.Close()
	if a := ln.Addr().(*net.TCPAddr); a.IP.String() != "127.0.0.1" || a.Port != ports[0] {
		t.Errorf("bound to %v", a)
	}
	c, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if _, err := f(held); err == nil {
		t.Error("a port held by another program must be skipped")
	}
	none := AddrListen(func() netip.Addr { return netip.Addr{} }, nil, net.ListenConfig{})
	if l, err := none(ports[1]); err == nil {
		l.Close()
		t.Error("no address: no listener (never on all addresses)")
	}
	if l, err := AddrListen(nil, nil, net.ListenConfig{})(ports[1]); err == nil {
		l.Close()
		t.Error("nil local must fail")
	}
}

func freePortsAny(t *testing.T, n int) []int {
	t.Helper()
	var ls []net.Listener
	var ports []int
	for i := 0; i < n; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Skip("no loopback:", err)
		}
		ls = append(ls, l)
		ports = append(ports, l.Addr().(*net.TCPAddr).Port)
	}
	for _, l := range ls {
		l.Close()
	}
	return ports
}
