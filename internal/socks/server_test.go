package socks

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func echoServer(t *testing.T) net.Addr {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return l.Addr()
}

func start(t *testing.T, s *Server) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go s.Serve(l)
	return l.Addr().String()
}

func dialer(ctx context.Context, n, a string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, n, a)
}

// request sends greeting + CONNECT and returns the reply code and the conn.
func request(t *testing.T, proxy string, req []byte) (byte, net.Conn) {
	c, err := net.Dial("tcp", proxy)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.Write([]byte{5, 1, 0})
	var m [2]byte
	if _, err := io.ReadFull(c, m[:]); err != nil || m[1] != 0 {
		t.Fatalf("method %v %v", m, err)
	}
	c.Write(req)
	var r [10]byte
	if _, err := io.ReadFull(c, r[:]); err != nil {
		t.Fatal(err)
	}
	return r[1], c
}

func TestConnectIPv4(t *testing.T) {
	target := echoServer(t).(*net.TCPAddr)
	p := start(t, &Server{Dial: dialer})
	req := append([]byte{5, 1, 0, 1}, target.IP.To4()...)
	req = append(req, byte(target.Port>>8), byte(target.Port))
	rep, c := request(t, p, req)
	if rep != 0 {
		t.Fatalf("reply %d", rep)
	}
	c.Write([]byte("hello"))
	buf := make([]byte, 5)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("echo %q %v", buf, err)
	}
}

func TestConnectNameUsesResolver(t *testing.T) {
	target := echoServer(t).(*net.TCPAddr)
	var asked string
	s := &Server{Dial: dialer, Resolve: func(_ context.Context, n string) ([]netip.Addr, error) {
		asked = n
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}}
	p := start(t, s)
	name := "svc.example"
	req := append([]byte{5, 1, 0, 3, byte(len(name))}, name...)
	req = append(req, byte(target.Port>>8), byte(target.Port))
	if rep, _ := request(t, p, req); rep != 0 || asked != name {
		t.Fatalf("reply %d, asked %q", rep, asked)
	}
}

// A dead tunnel must refuse, never fall back to another way.
func TestDialFailureRefuses(t *testing.T) {
	s := &Server{Dial: func(context.Context, string, string) (net.Conn, error) { return nil, io.ErrClosedPipe }}
	p := start(t, s)
	req := []byte{5, 1, 0, 1, 192, 0, 2, 1, 0, 80}
	if rep, _ := request(t, p, req); rep == 0 {
		t.Fatal("connect succeeded with a failing dialer")
	}
}

func TestOnlyConnect(t *testing.T) {
	p := start(t, &Server{Dial: dialer})
	if rep, _ := request(t, p, []byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0}); rep != repBadCommand {
		t.Fatalf("BIND reply %d", rep)
	}
}

func TestUDPAssociate(t *testing.T) {
	// UDP echo as the "world"
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		b := make([]byte, 2048)
		for {
			n, a, err := pc.ReadFrom(b)
			if err != nil {
				return
			}
			pc.WriteTo(b[:n], a)
		}
	}()
	s := &Server{Dial: dialer, ListenPacket: func(ctx context.Context, n, a string) (net.PacketConn, error) {
		return net.ListenPacket(n, "127.0.0.1:0")
	}}
	p := start(t, s)
	c, err := net.Dial("tcp", p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.Write([]byte{5, 1, 0})
	var m [2]byte
	io.ReadFull(c, m[:])
	c.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	var r [10]byte
	if _, err := io.ReadFull(c, r[:]); err != nil || r[1] != 0 {
		t.Fatalf("assoc %v %v", r, err)
	}
	relay := &net.UDPAddr{IP: net.IP(r[4:8]), Port: int(r[8])<<8 | int(r[9])}
	u, _ := net.DialUDP("udp", nil, relay)
	defer u.Close()
	dst := pc.LocalAddr().(*net.UDPAddr)
	pkt := append([]byte{0, 0, 0, 1, 127, 0, 0, 1, byte(dst.Port >> 8), byte(dst.Port)}, "ping"...)
	u.Write(pkt)
	u.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 100)
	n, err := u.Read(buf)
	if err != nil || string(buf[n-4:n]) != "ping" || buf[3] != 1 {
		t.Fatalf("reply %v %v", buf[:n], err)
	}
}

// DialVia against our own server, with a name that the far side resolves
// (Remote) and the client address reaching the Dial function.
func TestDialViaRemoteName(t *testing.T) {
	target := echoServer(t).(*net.TCPAddr)
	var gotHost string
	var gotClient net.Addr
	s := &Server{Remote: true, Dial: func(ctx context.Context, n, a string) (net.Conn, error) {
		gotHost, gotClient = a, ClientAddr(ctx)
		return dialer(ctx, n, target.String())
	}}
	p := start(t, s)
	c, err := DialVia(context.Background(), "tcp", p, "someapp", "hidden.onion:80")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("hi"))
	b := make([]byte, 2)
	if _, err := io.ReadFull(c, b); err != nil || string(b) != "hi" {
		t.Fatalf("%q %v", b, err)
	}
	if gotHost != "hidden.onion:80" || gotClient == nil {
		t.Fatalf("host %q client %v", gotHost, gotClient)
	}
}
