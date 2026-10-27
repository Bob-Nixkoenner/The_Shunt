// Package socks is the SOCKS5 exit of a tunnel: a program that is told to
// use 127.0.0.1:<port> as its proxy goes through that tunnel without a
// cgroup rule. The sockets leave with the tunnel's mark, so the kill switch
// (leak_guard) applies as to any routed app: tunnel down means refused,
// never direct. Only CONNECT with "socks5h" (the proxy resolves names).
package socks

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

const (
	ver5       = 5
	cmdConnect = 1
	cmdUDP     = 3
	atypIPv4   = 1
	atypName   = 3
	atypIPv6   = 4

	repOK          = 0
	repFailure     = 1
	repNotAllowed  = 2
	repNetDown     = 3
	repHostDown    = 4
	repRefused     = 5
	repBadCommand  = 7
	repBadAddrType = 8

	handshakeTimeout = 10 * time.Second
)

// Server answers SOCKS5 requests and forwards them through Dial.
type Server struct {
	// Dial opens the outgoing connection (marked for the tunnel).
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// ListenPacket opens the marked UDP socket of a UDP association
	// (nil: UDP ASSOCIATE is refused).
	ListenPacket func(ctx context.Context, network, addr string) (net.PacketConn, error)
	// Resolve looks a name up inside the tunnel (never on the local network).
	Resolve func(ctx context.Context, name string) ([]netip.Addr, error)
	Log     *slog.Logger

	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

// Serve accepts on l until it is closed.
func (s *Server) Serve(l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.handle(c)
	}
}

// SetResolve replaces the resolver (the tunnel's DNS upstreams change on reload).
func (s *Server) SetResolve(f func(ctx context.Context, name string) ([]netip.Addr, error)) {
	s.mu.Lock()
	s.Resolve = f
	s.mu.Unlock()
}

func (s *Server) resolver() func(ctx context.Context, name string) ([]netip.Addr, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Resolve
}

// CloseConns drops the connections still open (the listener was closed).
func (s *Server) CloseConns() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for c := range s.conns {
		_ = c.Close()
	}
}

func (s *Server) track(c net.Conn, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conns == nil {
		s.conns = map[net.Conn]struct{}{}
	}
	if add {
		s.conns[c] = struct{}{}
	} else {
		delete(s.conns, c)
	}
}

func (s *Server) handle(c net.Conn) {
	s.track(c, true)
	defer s.track(c, false)
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(handshakeTimeout))

	if err := negotiate(c); err != nil {
		return
	}
	cmd, host, port, rep, err := readRequest(c)
	if err != nil {
		reply(c, rep)
		return
	}
	if cmd == cmdUDP {
		s.associate(c)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
	defer cancel()
	out, rep := s.connect(ctx, host, port)
	if out == nil {
		reply(c, rep)
		return
	}
	defer out.Close()
	reply(c, repOK)
	_ = c.SetDeadline(time.Time{})

	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}
	go pipe(out, c)
	go pipe(c, out)
	<-done
	<-done
}

func (s *Server) connect(ctx context.Context, host string, port int) (net.Conn, byte) {
	var addrs []netip.Addr
	if a, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{a.Unmap()}
	} else {
		var err error
		resolve := s.resolver()
		if resolve == nil {
			return nil, repFailure
		}
		if addrs, err = resolve(ctx, host); err != nil || len(addrs) == 0 {
			return nil, repHostDown
		}
	}
	var last error
	for _, a := range addrs {
		c, err := s.Dial(ctx, "tcp", net.JoinHostPort(a.String(), strconv.Itoa(port)))
		if err == nil {
			return c, repOK
		}
		last = err
	}
	if s.Log != nil {
		s.Log.Debug("socks connect", "host", host, "err", last)
	}
	return nil, repFor(last)
}

func repFor(err error) byte {
	var ne net.Error
	switch {
	case errors.Is(err, errRefused):
		return repRefused
	case errors.As(err, &ne) && ne.Timeout():
		return repHostDown
	default:
		return repNetDown
	}
}

// negotiate accepts only "no authentication" (loopback listener).
func negotiate(c net.Conn) error {
	var h [2]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return err
	}
	if h[0] != ver5 {
		return fmt.Errorf("version %d", h[0])
	}
	methods := make([]byte, h[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return err
	}
	for _, m := range methods {
		if m == 0 {
			_, err := c.Write([]byte{ver5, 0})
			return err
		}
	}
	_, _ = c.Write([]byte{ver5, 0xff})
	return errors.New("no acceptable method")
}

func readRequest(c net.Conn) (cmd byte, host string, port int, rep byte, err error) {
	var h [4]byte
	if _, err = io.ReadFull(c, h[:]); err != nil {
		return 0, "", 0, repFailure, err
	}
	if h[0] != ver5 {
		return 0, "", 0, repFailure, errors.New("bad version")
	}
	if h[1] != cmdConnect && h[1] != cmdUDP {
		return 0, "", 0, repBadCommand, errors.New("only CONNECT and UDP ASSOCIATE")
	}
	switch h[3] {
	case atypIPv4:
		var b [4]byte
		if _, err = io.ReadFull(c, b[:]); err != nil {
			return 0, "", 0, repFailure, err
		}
		host = netip.AddrFrom4(b).String()
	case atypIPv6:
		var b [16]byte
		if _, err = io.ReadFull(c, b[:]); err != nil {
			return 0, "", 0, repFailure, err
		}
		host = netip.AddrFrom16(b).String()
	case atypName:
		var l [1]byte
		if _, err = io.ReadFull(c, l[:]); err != nil {
			return 0, "", 0, repFailure, err
		}
		b := make([]byte, l[0])
		if _, err = io.ReadFull(c, b); err != nil {
			return 0, "", 0, repFailure, err
		}
		host = string(b)
	default:
		return 0, "", 0, repBadAddrType, errors.New("address type")
	}
	var p [2]byte
	if _, err = io.ReadFull(c, p[:]); err != nil {
		return 0, "", 0, repFailure, err
	}
	return h[1], host, int(p[0])<<8 | int(p[1]), repOK, nil
}

func reply(c net.Conn, rep byte) {
	_, _ = c.Write([]byte{ver5, rep, 0, atypIPv4, 0, 0, 0, 0, 0, 0})
}
