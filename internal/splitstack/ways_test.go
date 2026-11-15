package splitstack

import (
	"io"
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

func TestWayConnHalfClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, _ := ln.Accept()
		io.Copy(io.Discard, c) // wait for the client's half-close
		c.Write([]byte("reply"))
		c.Close()
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c := &wayConn{Conn: raw, w: &wayCount{}}
	c.Write([]byte("req"))
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(c)
	if string(b) != "reply" {
		t.Fatalf("got %q, want reply after half-close", b)
	}
	raw.Close()
}
