package socks

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"time"
)

type ctxKey struct{}

// ClientAddr returns the address of the program that connected to the
// server, for the Dial function of a connection (nil if unknown).
func ClientAddr(ctx context.Context) net.Addr {
	a, _ := ctx.Value(ctxKey{}).(net.Addr)
	return a
}

// DialVia opens a connection to target ("host:port", the host may be a name)
// through the SOCKS5 server at network/addr. A non-empty user is sent as
// user name and password: Tor gives each different one its own circuits.
func DialVia(ctx context.Context, network, addr, user, target string) (net.Conn, error) {
	d := net.Dialer{Timeout: 10 * time.Second}
	c, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	} else {
		_ = c.SetDeadline(time.Now().Add(handshakeTimeout))
	}
	if err := handshake(c, user, target); err != nil {
		c.Close()
		return nil, err
	}
	_ = c.SetDeadline(time.Time{})
	return c, nil
}

func handshake(c net.Conn, user, target string) error {
	host, ps, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(ps)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("bad port in %q", target)
	}
	method := byte(0)
	if user != "" {
		method = 2
	}
	if _, err := c.Write([]byte{ver5, 1, method}); err != nil {
		return err
	}
	var m [2]byte
	if _, err := io.ReadFull(c, m[:]); err != nil {
		return err
	}
	if m[0] != ver5 || m[1] != method {
		return errors.New("socks server refused the authentication method")
	}
	if method == 2 {
		if len(user) > 255 {
			user = user[:255]
		}
		req := append([]byte{1, byte(len(user))}, user...)
		req = append(req, 1, 'x')
		if _, err := c.Write(req); err != nil {
			return err
		}
		var a [2]byte
		if _, err := io.ReadFull(c, a[:]); err != nil || a[1] != 0 {
			return errors.New("socks authentication failed")
		}
	}
	req := []byte{ver5, cmdConnect, 0}
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if ip.Is4() {
			req = append(req, atypIPv4)
		} else {
			req = append(req, atypIPv6)
		}
		req = append(req, ip.AsSlice()...)
	} else {
		if len(host) > 255 {
			return errors.New("name too long")
		}
		req = append(req, atypName, byte(len(host)))
		req = append(req, host...)
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		return err
	}
	var h [4]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return err
	}
	if h[1] != repOK {
		return &ReplyError{Code: h[1]}
	}
	skip := 0
	switch h[3] {
	case atypIPv4:
		skip = 4
	case atypIPv6:
		skip = 16
	case atypName:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return err
		}
		skip = int(l[0])
	}
	_, err = io.CopyN(io.Discard, c, int64(skip+2))
	return err
}

// ReplyError is a SOCKS5 failure code from the server.
type ReplyError struct{ Code byte }

func (e *ReplyError) Error() string { return fmt.Sprintf("socks reply %d", e.Code) }

// WithClientAddr returns ctx carrying the client's address (what
// ClientAddr returns), for connections not accepted by Server.
func WithClientAddr(ctx context.Context, a net.Addr) context.Context {
	return context.WithValue(ctx, ctxKey{}, a)
}

type userKey struct{}

// WithUser fixes the SOCKS user name (Tor's isolation key) for a connection.
func WithUser(ctx context.Context, u string) context.Context {
	return context.WithValue(ctx, userKey{}, u)
}

// UserOf returns what WithUser set ("" if nothing).
func UserOf(ctx context.Context) string {
	u, _ := ctx.Value(userKey{}).(string)
	return u
}

// Resolve asks a Tor SOCKS5 server (the RESOLVE extension, command 0xF0) to
// resolve name, so no DNSPort is needed. Tor answers with one address.
func Resolve(ctx context.Context, addr, user, name string) (netip.Addr, error) {
	d := net.Dialer{Timeout: 10 * time.Second}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return netip.Addr{}, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	} else {
		_ = c.SetDeadline(time.Now().Add(handshakeTimeout))
	}
	method := byte(0)
	if user != "" {
		method = 2
	}
	if _, err := c.Write([]byte{ver5, 1, method}); err != nil {
		return netip.Addr{}, err
	}
	var m [2]byte
	if _, err := io.ReadFull(c, m[:]); err != nil {
		return netip.Addr{}, err
	}
	if m[0] != ver5 || m[1] != method {
		return netip.Addr{}, errors.New("socks server refused the authentication method")
	}
	if method == 2 {
		req := append([]byte{1, byte(len(user))}, user...)
		req = append(req, 1, 'x')
		if _, err := c.Write(req); err != nil {
			return netip.Addr{}, err
		}
		var a [2]byte
		if _, err := io.ReadFull(c, a[:]); err != nil || a[1] != 0 {
			return netip.Addr{}, errors.New("socks authentication failed")
		}
	}
	if len(name) == 0 || len(name) > 255 {
		return netip.Addr{}, errors.New("bad name")
	}
	req := append([]byte{ver5, 0xF0, 0, atypName, byte(len(name))}, name...)
	req = append(req, 0, 0)
	if _, err := c.Write(req); err != nil {
		return netip.Addr{}, err
	}
	var h [4]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return netip.Addr{}, err
	}
	if h[1] != repOK {
		return netip.Addr{}, &ReplyError{Code: h[1]}
	}
	switch h[3] {
	case atypIPv4:
		var b [4]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			return netip.Addr{}, err
		}
		return netip.AddrFrom4(b), nil
	case atypIPv6:
		var b [16]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			return netip.Addr{}, err
		}
		return netip.AddrFrom16(b), nil
	}
	return netip.Addr{}, errors.New("resolve: unexpected answer type")
}
