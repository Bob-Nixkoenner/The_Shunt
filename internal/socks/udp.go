package socks

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"time"
)

const maxDatagram = 65535

// associate serves UDP ASSOCIATE: a loopback UDP socket for the client and a
// marked one towards the world. It lives as long as the TCP control
// connection c. Only the client's own address may use it.
func (s *Server) associate(c net.Conn) {
	if s.ListenPacket == nil {
		reply(c, repBadCommand)
		return
	}
	ra, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok || !ra.IP.IsLoopback() {
		reply(c, repNotAllowed)
		return
	}
	lo := "127.0.0.1"
	if ra.IP.To4() == nil {
		lo = "::1"
	}
	ctx := context.Background()
	local, err := net.ListenPacket("udp", net.JoinHostPort(lo, "0"))
	if err != nil {
		reply(c, repFailure)
		return
	}
	defer local.Close()
	world, err := s.ListenPacket(ctx, "udp", ":0")
	if err != nil {
		reply(c, repFailure)
		return
	}
	defer world.Close()
	la := local.LocalAddr().(*net.UDPAddr)
	// BND.ADDR = the loopback address, BND.PORT = the relay port
	rep := []byte{ver5, repOK, 0, atypIPv4}
	if la.IP.To4() != nil {
		rep = append(rep, la.IP.To4()...)
	} else {
		rep[3] = atypIPv6
		rep = append(rep, la.IP.To16()...)
	}
	rep = binary.BigEndian.AppendUint16(rep, uint16(la.Port))
	_ = c.SetDeadline(time.Time{})
	if _, err := c.Write(rep); err != nil {
		return
	}

	var client atomic.Pointer[net.UDPAddr]
	// client -> world
	go func() {
		buf := make([]byte, maxDatagram)
		for {
			n, from, err := local.ReadFrom(buf)
			if err != nil {
				return
			}
			fa := from.(*net.UDPAddr)
			if !fa.IP.Equal(ra.IP) {
				continue // not the client that opened the association
			}
			client.Store(fa)
			host, port, data, err := parseUDP(buf[:n])
			if err != nil {
				continue
			}
			dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			dst, err := s.udpDest(dctx, host, port)
			cancel()
			if err != nil {
				continue
			}
			_, _ = world.WriteTo(data, dst)
		}
	}()
	// world -> client
	go func() {
		buf := make([]byte, maxDatagram)
		for {
			n, from, err := world.ReadFrom(buf)
			if err != nil {
				return
			}
			dstc := client.Load()
			if dstc == nil {
				continue
			}
			ua, ok := from.(*net.UDPAddr)
			if !ok {
				continue
			}
			_, _ = local.WriteTo(append(udpHeader(ua), buf[:n]...), dstc)
		}
	}()
	// the association ends with the control connection
	_, _ = drain(c)
}

func drain(c net.Conn) (int64, error) {
	buf := make([]byte, 512)
	var n int64
	for {
		k, err := c.Read(buf)
		n += int64(k)
		if err != nil {
			return n, err
		}
	}
}

func (s *Server) udpDest(ctx context.Context, host string, port int) (*net.UDPAddr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		return net.UDPAddrFromAddrPort(netip.AddrPortFrom(a.Unmap(), uint16(port))), nil
	}
	resolve := s.resolver()
	if resolve == nil {
		return nil, errors.New("no resolver")
	}
	addrs, err := resolve(ctx, host)
	if err != nil || len(addrs) == 0 {
		return nil, errors.New("cannot resolve " + strconv.Quote(host))
	}
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(addrs[0], uint16(port))), nil
}

// parseUDP reads RSV(2) FRAG ATYP ADDR PORT DATA; fragments are dropped.
func parseUDP(b []byte) (host string, port int, data []byte, err error) {
	bad := errors.New("bad udp request")
	if len(b) < 4 || b[2] != 0 {
		return "", 0, nil, bad
	}
	i := 4
	switch b[3] {
	case atypIPv4:
		if len(b) < i+4 {
			return "", 0, nil, bad
		}
		host = netip.AddrFrom4([4]byte(b[i : i+4])).String()
		i += 4
	case atypIPv6:
		if len(b) < i+16 {
			return "", 0, nil, bad
		}
		host = netip.AddrFrom16([16]byte(b[i : i+16])).String()
		i += 16
	case atypName:
		if len(b) < i+1 || len(b) < i+1+int(b[i]) {
			return "", 0, nil, bad
		}
		l := int(b[i])
		host = string(b[i+1 : i+1+l])
		i += 1 + l
	default:
		return "", 0, nil, bad
	}
	if len(b) < i+2 {
		return "", 0, nil, bad
	}
	return host, int(binary.BigEndian.Uint16(b[i:])), b[i+2:], nil
}

func udpHeader(a *net.UDPAddr) []byte {
	h := []byte{0, 0, 0}
	if ip4 := a.IP.To4(); ip4 != nil {
		h = append(h, atypIPv4)
		h = append(h, ip4...)
	} else {
		h = append(h, atypIPv6)
		h = append(h, a.IP.To16()...)
	}
	return binary.BigEndian.AppendUint16(h, uint16(a.Port))
}
