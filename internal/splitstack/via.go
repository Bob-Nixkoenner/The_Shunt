package splitstack

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// Multi-hop for OpenVPN (tunnelConf.Via): openvpn runs outside the VPN (the
// app is excluded from its own VPN), so it cannot reach a server that is
// only reachable through another tunnel. Each "remote" of the .ovpn is
// replaced by a relay on 127.0.0.1 that carries the packets (UDP) or the
// stream (TCP) through the netstack of the outer WireGuard tunnel.

// dialFunc dials through the outer tunnel (netstack.Net.DialContext).
type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// viaRelay is the set of local relays for one OpenVPN tunnel.
type viaRelay struct {
	mu      sync.Mutex
	closers []io.Closer
	done    chan struct{}
	once    sync.Once
}

func (r *viaRelay) add(c io.Closer) {
	r.mu.Lock()
	r.closers = append(r.closers, c)
	r.mu.Unlock()
}

// Close stops all relays and their connections.
func (r *viaRelay) Close() error {
	r.once.Do(func() {
		close(r.done)
		r.mu.Lock()
		for _, c := range r.closers {
			c.Close()
		}
		r.mu.Unlock()
	})
	return nil
}

// viaIdle: a UDP upstream without traffic for this long is dropped (a new
// one is dialed with the next packet).
var viaIdle = 3 * time.Minute

// viaRewrite starts one relay per "remote" line and returns the .ovpn with
// these lines pointing to the relays. Port and protocol come from the line,
// else from "port"/"proto", else 1194/udp (OpenVPN defaults).
func viaRewrite(conf string, dial dialFunc) (string, *viaRelay, error) {
	port, proto := "1194", "udp"
	lines := strings.Split(conf, "\n")
	for _, l := range lines { // inline blocks never start with these words
		f := strings.Fields(l)
		if len(f) >= 2 && f[0] == "port" {
			port = f[1]
		}
		if len(f) >= 2 && f[0] == "proto" {
			proto = f[1]
		}
	}
	r := &viaRelay{done: make(chan struct{})}
	n := 0
	inline := false // inside <ca>…</ca> and the like: not options
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "<") {
			inline = !strings.HasPrefix(t, "</")
			continue
		}
		f := strings.Fields(l)
		if inline || len(f) < 2 || f[0] != "remote" {
			continue
		}
		host, p, pr := f[1], port, proto
		if len(f) >= 3 {
			p = f[2]
		}
		if len(f) >= 4 {
			pr = f[3]
		}
		target := net.JoinHostPort(host, p)
		var local string
		var err error
		if strings.HasPrefix(pr, "tcp") {
			local, err = r.tcp(target, dial)
			pr = "tcp-client"
		} else {
			local, err = r.udp(target, dial)
			pr = "udp"
		}
		if err != nil {
			r.Close()
			return "", nil, err
		}
		_, lp, _ := net.SplitHostPort(local)
		lines[i] = fmt.Sprintf("remote 127.0.0.1 %s %s # via: %s", lp, pr, target)
		n++
	}
	if n == 0 {
		r.Close()
		return "", nil, errors.New("no remote (server) in the file")
	}
	return strings.Join(lines, "\n"), r, nil
}

// tcp: every local connection becomes one connection through the tunnel.
func (r *viaRelay) tcp(target string, dial dialFunc) (string, error) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	r.add(ln)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				up, err := dial(ctx, "tcp", target)
				cancel()
				if err != nil {
					return
				}
				defer up.Close()
				go func() { io.Copy(up, c); up.Close() }()
				io.Copy(c, up)
			}()
		}
	}()
	return ln.Addr().String(), nil
}

// udp: packets from openvpn go to target through the tunnel, answers go
// back to the last local sender (one openvpn per relay).
func (r *viaRelay) udp(target string, dial dialFunc) (string, error) {
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return "", err
	}
	r.add(pc)
	var mu sync.Mutex
	var up net.Conn
	var peer *net.UDPAddr
	upstream := func() (net.Conn, error) {
		mu.Lock()
		defer mu.Unlock()
		if up != nil {
			return up, nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		c, err := dial(ctx, "udp", target)
		if err != nil {
			return nil, err
		}
		up = c
		r.add(c)
		go func() { // answers back to openvpn
			buf := make([]byte, 65535)
			for {
				c.SetReadDeadline(time.Now().Add(viaIdle))
				n, err := c.Read(buf)
				if err != nil {
					mu.Lock()
					if up == c {
						up = nil
					}
					mu.Unlock()
					c.Close()
					return
				}
				mu.Lock()
				to := peer
				mu.Unlock()
				if to != nil {
					pc.WriteToUDP(buf[:n], to)
				}
			}
		}()
		return c, nil
	}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			mu.Lock()
			peer = from
			mu.Unlock()
			c, err := upstream()
			if err != nil {
				continue // openvpn retries; the outer tunnel may come up later
			}
			if _, err := c.Write(buf[:n]); err != nil {
				mu.Lock()
				if up == c {
					up = nil
				}
				mu.Unlock()
				c.Close()
			}
		}
	}()
	return pc.LocalAddr().String(), nil
}
