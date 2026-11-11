package defense

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
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
	JA3    string // TLS client fingerprint when the hit carried a ClientHello
}

// DecoyOptions says which extras are on.
type DecoyOptions struct {
	Tarpit bool
	Cowrie bool
}

// Decoys runs the TCP decoy listeners.
type Decoys struct {
	Listen      ListenFunc
	OnHit       func(Hit)
	Tarpit      *Tarpit
	HostKeyPath string        // ssh decoy host key file ("" = memory only)
	SSHBanner   string        // ssh version string (default DefaultSSHBanner)
	SSHDelay    time.Duration // pause after every refused ssh login (tarpit)
	MaxConns    int           // simultaneous handlers over all ports (default 64)
	Timeout     time.Duration // per-connection limit for normal decoys (default 15 s)
	PerSource   int           // simultaneous handlers for one source address (default 8)
	Log         *slog.Logger  // for caught internal errors (nil = default)

	mu      sync.Mutex
	lns     map[int]net.Listener
	skipped map[int]string
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	sem     chan struct{}
	srcMu   sync.Mutex
	perSrc  map[netip.Addr]int

	keyMu  sync.Mutex
	signer ssh.Signer
	sshSem chan struct{}
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
	d.sshSem = make(chan struct{}, sshMaxConc)
	d.srcMu.Lock()
	d.perSrc = map[netip.Addr]int{}
	d.srcMu.Unlock()
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
		go func() {
			defer d.wg.Done()
			GuardLoop(ctx, d.Log, "decoy accept loop", func() { d.accept(ctx, ln, p, opt) })
		}()
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
	var backoff time.Duration
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			// out of file descriptors, aborted handshake, ...: wait and go
			// on instead of leaving the port dead until the next restart
			if backoff == 0 {
				backoff = 5 * time.Millisecond
			} else if backoff *= 2; backoff > time.Second {
				backoff = time.Second
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			continue
		}
		backoff = 0
		select {
		case d.sem <- struct{}{}:
		default:
			c.Close() // too many at once
			continue
		}
		src := addrOf(c.RemoteAddr())
		if !d.takeSource(src) {
			<-d.sem
			c.Close() // one source must not take every slot
			continue
		}
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			defer func() { <-d.sem }()
			defer d.dropSource(src)
			if Guard(d.Log, "decoy handler", func() { d.handle(ctx, c, port, opt) }) {
				c.Close() // a bug must cost this connection, not the daemon
			}
		}()
	}
}

func (d *Decoys) takeSource(a netip.Addr) bool {
	max := d.PerSource
	if max <= 0 {
		max = 8
	}
	d.srcMu.Lock()
	defer d.srcMu.Unlock()
	if d.perSrc[a] >= max {
		return false
	}
	d.perSrc[a]++
	return true
}

func (d *Decoys) dropSource(a netip.Addr) {
	d.srcMu.Lock()
	defer d.srcMu.Unlock()
	if d.perSrc[a]--; d.perSrc[a] <= 0 {
		delete(d.perSrc, a)
	}
}

// Banner returns what a decoy on port says first ("" = silent).
func Banner(port int) string {
	switch port {
	case 21:
		return "220 FTP server ready\r\n"
	case 22, 2222:
		return DefaultSSHBanner + "\r\n"
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

func isTelnetPort(p int) bool { return p == 23 || p == 2323 }
func isSSHPort(p int) bool    { return p == 22 || p == 2222 }

func (d *Decoys) handle(ctx context.Context, c net.Conn, port int, opt DecoyOptions) {
	src := addrOf(c.RemoteAddr())
	defer context.AfterFunc(ctx, func() { c.Close() })() // Stop must not wait for slow peers
	to := d.Timeout
	if to <= 0 {
		to = 15 * time.Second
	}
	d.hit(Hit{Src: src, Port: port, Kind: KindDecoyHit, Sev: SevMedium, Detail: "tcp connect"})

	if port == 443 {
		d.tlsHello(c, src, port)
	}
	if opt.Cowrie && (isTelnetPort(port) || isSSHPort(port)) {
		_ = c.SetDeadline(time.Now().Add(to * 4))
		if isTelnetPort(port) {
			telnetTrap(c, src, port, d.hit)
		} else {
			d.sshTrap(ctx, c, src, port)
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

// tlsHello reads the first bytes of a connection on the TLS decoy and, if it
// is a ClientHello, reports its JA3 fingerprint. Waits at most 2 s.
func (d *Decoys) tlsHello(c net.Conn, src netip.Addr, port int) {
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	n, _ := io.ReadAtLeast(c, buf, 11)
	_ = c.SetReadDeadline(time.Time{})
	if n < 11 {
		return
	}
	if _, h, ok := JA3(buf[:n]); ok {
		d.hit(Hit{Src: src, Port: port, Kind: KindObservation, Sev: SevInfo, Detail: "ja3=" + h, JA3: h})
	}
}
