package defense

import (
	"net/netip"
	"os"
	"path/filepath"
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
