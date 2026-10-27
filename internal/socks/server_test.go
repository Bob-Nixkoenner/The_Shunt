package socks

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
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
	if rep, _ := request(t, p, []byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); rep != repBadCommand {
		t.Fatalf("UDP ASSOCIATE reply %d", rep)
	}
}
