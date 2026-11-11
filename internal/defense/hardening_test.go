package defense

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

// One source flooding SYNs to many ports within the window: memory per
// source stays capped and the scan is still found.
func TestDetectorFloodOneSource(t *testing.T) {
	d := NewDetector(DetectConfig{}, nil)
	found := 0
	d.OnFound = func(Finding) { found++ }
	src := netip.MustParseAddr("192.0.2.7")
	start := time.Now()
	for i := 0; i < 100000; i++ {
		d.ObserveState(src, 1+i%60000, "tcp", StateS0)
	}
	if el := time.Since(start); el > 10*time.Second {
		t.Fatalf("flood took %v", el)
	}
	st := d.src[src]
	if len(st.fails) > maxTrackedFails || len(st.ports) > maxTrackedPorts {
		t.Fatalf("fails=%d ports=%d", len(st.fails), len(st.ports))
	}
	if found == 0 {
		t.Fatal("scan not found")
	}
}

// Ban spoofing: forged sources that cannot be a remote peer, and this
// machine's own addresses, are never blocked, by detection or by hand.
func TestBannable(t *testing.T) {
	own := netip.MustParseAddr("198.51.100.10")
	m := NewManager(nil, WithOwnAddr(func(a netip.Addr) bool { return a == own }))
	defer m.Close()
	m.SetNever([]netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")})
	for _, s := range []string{"0.0.0.0", "0.1.2.3", "255.255.255.255", "224.0.0.1", "ff02::1", "::", "198.51.100.10", "::ffff:198.51.100.10", "192.0.2.1"} {
		if m.Bannable(netip.MustParseAddr(s)) {
			t.Errorf("%s bannable", s)
		}
	}
	for _, s := range []string{"203.0.113.5", "2001:db8::5", "fe80::1", "192.0.2.2"} {
		if !m.Bannable(netip.MustParseAddr(s)) {
			t.Errorf("%s not bannable", s)
		}
	}
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Features[FeatScan] = Feature{Watch: true, Block: true}
	m.Configure(cfg)
	for p := 1; p <= 10; p++ {
		m.ObserveState(own, p, "tcp", StateS0)
		m.ObserveState(netip.MustParseAddr("255.255.255.255"), p, "udp", StateS0)
	}
	if n := len(m.Status().Bans); n != 0 {
		t.Fatalf("%d bans from forged sources", n)
	}
	if err := m.Ban("198.51.100.10"); err != ErrNotBannable {
		t.Fatalf("manual ban of own address: %v", err)
	}
}

func TestHostKeyHardening(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "k")
	s1, err := LoadOrCreateHostKey(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	// looser rights are cut back, the key stays the same
	_ = os.Chmod(p, 0o644)
	s2, err := LoadOrCreateHostKey(p)
	if err != nil || string(s2.PublicKey().Marshal()) != string(s1.PublicKey().Marshal()) {
		t.Fatalf("reload: %v", err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode after reload %v", fi.Mode())
	}
	// a damaged file is moved aside and replaced
	_ = os.WriteFile(p, []byte("garbage"), 0o600)
	if _, err := LoadOrCreateHostKey(p); err != nil {
		t.Fatalf("damaged key: %v", err)
	}
	if _, err := os.Stat(p + ".bad"); err != nil {
		t.Fatal("damaged key not kept aside")
	}
	// a symbolic link is refused, its target untouched
	target := filepath.Join(dir, "target")
	_ = os.WriteFile(target, []byte("x"), 0o644)
	l := filepath.Join(dir, "link")
	if err := os.Symlink(target, l); err != nil {
		t.Skip("no symlinks")
	}
	if _, err := LoadOrCreateHostKey(l); err == nil {
		t.Fatal("symlink accepted")
	}
	if b, _ := os.ReadFile(target); string(b) != "x" {
		t.Fatal("target changed")
	}
}

// Load: many simultaneous connections from one source (slowloris against
// the decoys and the tarpit). Handlers and traps stay within their caps,
// and Stop leaves no goroutine behind.
func TestDecoyLoadOneSource(t *testing.T) {
	if testing.Short() {
		t.Skip("load test")
	}
	pm := &portMap{real: map[int]int{}}
	var hits atomic.Int64
	d := NewDecoys(pm.listen, func(Hit) { hits.Add(1) })
	d.Tarpit = &Tarpit{Interval: 50 * time.Millisecond, MaxHold: 2 * time.Second}
	before := runtime.NumGoroutine()
	d.Start([]int{80, 23}, DecoyOptions{Tarpit: true})
	var conns []net.Conn
	for i := 0; i < 200; i++ {
		port := 80
		if i%2 == 1 {
			port = 23
		}
		c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(pm.real[port])), time.Second)
		if err != nil {
			continue
		}
		conns = append(conns, c) // never send, never close: hold every slot we can
	}
	time.Sleep(300 * time.Millisecond)
	if a := d.Tarpit.Active(); a > 4 {
		t.Fatalf("one source holds %d traps (cap 4)", a)
	}
	d.srcMu.Lock()
	n := d.perSrc[netip.MustParseAddr("127.0.0.1")]
	d.srcMu.Unlock()
	if n > 8 {
		t.Fatalf("one source holds %d handlers (cap 8)", n)
	}
	for _, c := range conns {
		c.Close()
	}
	d.Stop()
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > before+2 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if g := runtime.NumGoroutine(); g > before+2 {
		t.Fatalf("goroutines %d -> %d after Stop", before, g)
	}
	if hits.Load() == 0 {
		t.Fatal("no hits")
	}
}

// Load: many sources. The global caps hold and the tarpit is freed again.
func TestTarpitManySources(t *testing.T) {
	tp := &Tarpit{Interval: 20 * time.Millisecond, MaxHold: 200 * time.Millisecond, MaxConns: 10}
	ctx := context.Background()
	held := 0
	for i := 0; i < 50; i++ {
		a, b := net.Pipe()
		defer b.Close()
		pc := &addrConn{Conn: a, remote: &net.TCPAddr{IP: net.IPv4(192, 0, 2, byte(i+1)), Port: 1000}}
		if tp.TryHold(ctx, pc, nil) {
			held++
		} else {
			a.Close()
		}
	}
	if held != 10 || tp.Active() != 10 {
		t.Fatalf("held %d active %d", held, tp.Active())
	}
	deadline := time.Now().Add(3 * time.Second)
	for tp.Active() > 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	tp.mu.Lock()
	left := len(tp.bySrc)
	tp.mu.Unlock()
	if tp.Active() != 0 || left != 0 {
		t.Fatalf("active %d, sources left %d", tp.Active(), left)
	}
}

type addrConn struct {
	net.Conn
	remote net.Addr
}

func (c *addrConn) RemoteAddr() net.Addr { return c.remote }

// Load: the ban table and the event ring stay at their caps under a flood
// of distinct sources.
func TestBanAndRingCaps(t *testing.T) {
	b := NewBans()
	b.Max = 512
	for i := 0; i < 5000; i++ {
		b.Add(netip.AddrFrom4([4]byte{198, 51, byte(i >> 8), byte(i)}).String(), KindScan, time.Hour)
	}
	if b.Len() != 512 {
		t.Fatalf("bans %d", b.Len())
	}
	r := NewRing(100)
	for i := 0; i < 10000; i++ {
		r.Add(Event{Kind: KindDecoyHit})
	}
	if ev := r.Events(0); len(ev.Events) != 100 || ev.LastSeq != 10000 {
		t.Fatalf("ring %d last %d", len(ev.Events), ev.LastSeq)
	}
}

// An Accept error that is not "closed" (EMFILE, ECONNABORTED) must not end
// the decoy port for good.
func TestDecoyAcceptRecovers(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fl := &flakyListener{Listener: inner}
	fl.fails.Store(3)
	got := make(chan Hit, 4)
	d := NewDecoys(func(int) (net.Listener, error) { return fl, nil }, func(h Hit) { got <- h })
	d.Start([]int{8080}, DecoyOptions{})
	defer d.Stop()
	c, err := net.Dial("tcp", inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	select {
	case <-got:
	case <-time.After(3 * time.Second):
		t.Fatal("decoy stopped accepting after transient errors")
	}
}

type flakyListener struct {
	net.Listener
	fails atomic.Int32
}

func (f *flakyListener) Accept() (net.Conn, error) {
	if f.fails.Add(-1) >= 0 {
		return nil, errors.New("accept4: too many open files")
	}
	return f.Listener.Accept()
}
