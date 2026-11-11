package defense

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"time"
)

// ListenFunc opens a TCP listener for a decoy port. The Linux side replaces
// it to set SO_MARK or bind to an interface.
type ListenFunc func(port int) (net.Listener, error)

// DefaultListen listens on all addresses.
func DefaultListen(port int) (net.Listener, error) {
	return net.Listen("tcp", net.JoinHostPort("", strconv.Itoa(port)))
}

// Hit is one connection to a decoy port.
type Hit struct {
	Src    netip.Addr
	Port   int
	Kind   Kind
	Sev    Severity
	Detail string
}

// DecoyOptions says which extras are on.
type DecoyOptions struct {
	Tarpit bool
	Cowrie bool
}

// Decoys runs the TCP decoy listeners.
type Decoys struct {
	Listen   ListenFunc
	OnHit    func(Hit)
	Tarpit   *Tarpit
	MaxConns int           // simultaneous handlers over all ports (default 64)
	Timeout  time.Duration // per-connection limit for normal decoys (default 15 s)

	mu      sync.Mutex
	lns     map[int]net.Listener
	skipped map[int]string
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	sem     chan struct{}
}

// NewDecoys returns a stopped decoy set.
func NewDecoys(listen ListenFunc, onHit func(Hit)) *Decoys {
	if listen == nil {
		listen = DefaultListen
	}
	return &Decoys{Listen: listen, OnHit: onHit, Tarpit: &Tarpit{}}
}

// Start replaces the running listeners by ports. Ports that cannot be
// opened (in use, no rights) are skipped and remembered in Skipped.
func (d *Decoys) Start(ports []int, opt DecoyOptions) {
	d.Stop()
	d.mu.Lock()
	defer d.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	d.cancel = cancel
	d.lns = map[int]net.Listener{}
	d.skipped = map[int]string{}
	n := d.MaxConns
	if n <= 0 {
		n = 64
	}
	d.sem = make(chan struct{}, n)
	for _, p := range ports {
		if p <= 0 || p > 65535 || d.lns[p] != nil {
			continue
		}
		ln, err := d.Listen(p)
		if err != nil {
			d.skipped[p] = err.Error()
			continue
		}
		d.lns[p] = ln
		d.wg.Add(1)
		go d.accept(ctx, ln, p, opt)
	}
}

// Stop closes all listeners and waits for the accept loops.
func (d *Decoys) Stop() {
	d.mu.Lock()
	if d.cancel != nil {
		d.cancel()
		d.cancel = nil
	}
	for _, ln := range d.lns {
		ln.Close()
	}
	d.lns = nil
	d.mu.Unlock()
	d.wg.Wait()
}

// Ports lists the ports that are really listening, sorted.
func (d *Decoys) Ports() []int {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]int, 0, len(d.lns))
	for p := range d.lns {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

// Skipped lists the ports that could not be opened with the reason.
func (d *Decoys) Skipped() map[int]string {
	d.mu.Lock()
	defer d.mu.Unlock()
	m := make(map[int]string, len(d.skipped))
	for k, v := range d.skipped {
		m[k] = v
	}
	return m
}

func (d *Decoys) hit(h Hit) {
	if d.OnHit != nil {
		d.OnHit(h)
	}
}

func (d *Decoys) accept(ctx context.Context, ln net.Listener, port int, opt DecoyOptions) {
	defer d.wg.Done()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		select {
		case d.sem <- struct{}{}:
		default:
			c.Close() // too many at once
			continue
		}
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			defer func() { <-d.sem }()
			d.handle(ctx, c, port, opt)
		}()
	}
}

// Banner returns what a decoy on port says first ("" = silent).
func Banner(port int) string {
	switch port {
	case 21:
		return "220 FTP server ready\r\n"
	case 22:
		return "SSH-2.0-OpenSSH_9.6\r\n"
	case 25, 587:
		return "220 mail ESMTP Postfix\r\n"
	case 80, 8080:
		return "HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
	case 443:
		return "" // TLS: stay silent, the client speaks first
	case 445, 3389:
		return ""
	}
	return ""
}

func (d *Decoys) handle(ctx context.Context, c net.Conn, port int, opt DecoyOptions) {
	src := addrOf(c.RemoteAddr())
	defer context.AfterFunc(ctx, func() { c.Close() })() // Stop must not wait for slow peers
	to := d.Timeout
	if to <= 0 {
		to = 15 * time.Second
	}
	d.hit(Hit{Src: src, Port: port, Kind: KindDecoyHit, Sev: SevMedium, Detail: "tcp connect"})

	if opt.Cowrie && (port == 23 || port == 22) {
		_ = c.SetDeadline(time.Now().Add(to * 4))
		if port == 23 {
			telnetTrap(c, src, port, d.hit)
		} else {
			sshBannerTrap(c, src, port, d.hit)
		}
		c.Close()
		return
	}
	if opt.Tarpit && d.Tarpit != nil {
		if b := Banner(port); b != "" {
			_ = c.SetWriteDeadline(time.Now().Add(to))
			_, _ = c.Write([]byte(b))
		}
		if d.Tarpit.TryHold(ctx, c, func(h time.Duration) {
			d.hit(Hit{Src: src, Port: port, Kind: KindTarpit, Sev: SevLow, Detail: fmt.Sprintf("held %ds", int(h.Seconds()))})
		}) {
			return
		}
		c.Close() // all traps busy: do not tie up a handler
		return
	}
	_ = c.SetDeadline(time.Now().Add(to))
	if b := Banner(port); b != "" {
		_, _ = c.Write([]byte(b))
	}
	buf := make([]byte, 512)
	_, _ = c.Read(buf)
	c.Close()
}

func addrOf(a net.Addr) netip.Addr {
	if t, ok := a.(*net.TCPAddr); ok {
		if ip, ok := netip.AddrFromSlice(t.IP); ok {
			return ip.Unmap()
		}
	}
	if ap, err := netip.ParseAddrPort(a.String()); err == nil {
		return ap.Addr().Unmap()
	}
	return netip.Addr{}
}
