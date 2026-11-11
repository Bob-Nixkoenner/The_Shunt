package defense

import (
	"fmt"
	"math/rand"
	"net/netip"
	"testing"
	"time"
)

func randLabel(r *rand.Rand, n int) string {
	const a = "abcdefghijklmnopqrstuvwxyz234567"
	b := make([]byte, n)
	for i := range b {
		b[i] = a[r.Intn(len(a))]
	}
	return string(b)
}

func enabledManager(t *testing.T, mods ...func(*Config)) (*Manager, *fakeClock) {
	t.Helper()
	clk := newClock()
	m := NewManager(nil, WithClock(clk.Now))
	t.Cleanup(m.Close)
	cfg := DefaultConfig()
	cfg.Enabled = true
	for _, f := range mods {
		f(&cfg)
	}
	m.Configure(cfg)
	m.SetNetwork("net-test", ClassPublic)
	return m, clk
}

func countKind(m *Manager, k Kind) (n int, last Event) {
	for _, e := range m.Events(0).Events {
		if e.Kind == k {
			n++
			last = e
		}
	}
	return
}

func TestBaseDomain(t *testing.T) {
	for in, want := range map[string]string{
		"a.b.Example.com.": "example.com", "example.com": "example.com", "x.y.example.co.uk": "example.co.uk",
		"localhost": "localhost", "a.example.test": "example.test",
	} {
		if got := BaseDomain(in); got != want {
			t.Errorf("BaseDomain(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDNSTunnelEvent(t *testing.T) {
	m, clk := enabledManager(t)
	cl := netip.MustParseAddr("192.0.2.9")
	// normal browsing: many names, short labels, nothing fires
	for i := 0; i < 40; i++ {
		m.ObserveDNS(cl, "www.example.org", "A")
		m.ObserveDNS(cl, fmt.Sprintf("cdn%d.example.net", i), "A")
		clk.Add(time.Second)
	}
	if n, _ := countKind(m, KindDNSTunnel); n != 0 {
		t.Fatalf("normal traffic raised %d events", n)
	}
	// a tunnel: long random labels + TXT
	r := rand.New(rand.NewSource(1))
	for i := 0; i < 20; i++ {
		m.ObserveDNS(cl, randLabel(r, 45)+".t.tunnel.example", "TXT")
		clk.Add(time.Second)
	}
	n, ev := countKind(m, KindDNSTunnel)
	if n != 1 {
		t.Fatalf("want exactly one event (cooldown), got %d", n)
	}
	if want := "domain=tunnel.example "; len(ev.Detail) < len(want) || ev.Detail[:len(want)] != want {
		t.Fatalf("detail %q", ev.Detail)
	}
	for _, e := range m.Events(0).Events {
		if len(e.Detail) > 100 {
			t.Fatalf("detail too long (carries labels?): %q", e.Detail)
		}
	}
	// after the cooldown it can fire again
	clk.Add(dnsCooldown)
	for i := 0; i < 8; i++ {
		m.ObserveDNS(cl, randLabel(r, 45)+".t.tunnel.example", "TXT")
		clk.Add(time.Second)
	}
	if n, _ := countKind(m, KindDNSTunnel); n != 2 {
		t.Fatalf("after cooldown: %d events", n)
	}
}

func TestDNSTunnelOffAndCap(t *testing.T) {
	m, clk := enabledManager(t, func(c *Config) { c.Features[FeatDNSTunnel] = Feature{} })
	cl := netip.MustParseAddr("192.0.2.9")
	r := rand.New(rand.NewSource(2))
	for i := 0; i < 30; i++ {
		m.ObserveDNS(cl, randLabel(r, 50)+".off.example", "TXT")
	}
	if n, _ := countKind(m, KindDNSTunnel); n != 0 {
		t.Fatal("feature off must stay silent")
	}
	m2, _ := enabledManager(t)
	for i := 0; i < dnsMaxKeys*2; i++ {
		m2.ObserveDNS(cl, fmt.Sprintf("x.d%d.example", i), "A")
	}
	m2.dns.mu.Lock()
	n := len(m2.dns.keys)
	m2.dns.mu.Unlock()
	if n > dnsMaxKeys {
		t.Fatalf("keys %d over cap", n)
	}
	_ = clk
}
