package defense

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

func TestBeaconFromConns(t *testing.T) {
	m, clk := enabledManager(t)
	dst := ap("198.51.100.20:8443")
	// regular: every 60 s from the same app
	for i := 0; i < 12; i++ {
		m.NoteConn("updater-x", dst, true)
		clk.Add(60 * time.Second)
	}
	n, ev := countKind(m, KindBeacon)
	if n != 1 {
		t.Fatalf("beacon events %d", n)
	}
	if ev.Src != "198.51.100.20" || ev.Port != 8443 || ev.Detail[:len("app=updater-x ")] != "app=updater-x " {
		t.Fatalf("event %+v", ev)
	}
	// irregular gaps: nothing
	gaps := []int{3, 47, 11, 90, 5, 33, 71, 8, 59, 2, 40, 17}
	for _, g := range gaps {
		m.NoteConn("browser", ap("203.0.113.5:443"), true)
		clk.Add(time.Duration(g) * time.Second)
	}
	if n, _ := countKind(m, KindBeacon); n != 1 {
		t.Fatalf("irregular traffic flagged (%d)", n)
	}
	// connections that already existed never count as beacon events
	m2, clk2 := enabledManager(t)
	for i := 0; i < 12; i++ {
		m2.NoteConn("x", dst, false)
		clk2.Add(60 * time.Second)
	}
	if n, _ := countKind(m2, KindBeacon); n != 0 {
		t.Fatal("existing connections counted")
	}
}

func TestBeaconExemptions(t *testing.T) {
	m, clk := enabledManager(t)
	for i := 0; i < 20; i++ {
		m.NoteConn("systemd-timesyncd", ap("198.51.100.1:443"), true)
		m.NoteConn("shuntd", ap("198.51.100.2:443"), true)
		m.NoteConn("someapp", ap("198.51.100.3:123"), true)
		m.NoteConn("someapp", ap("127.0.0.1:9000"), true)
		clk.Add(30 * time.Second)
	}
	if n, _ := countKind(m, KindBeacon); n != 0 {
		t.Fatalf("exempt traffic flagged: %d", n)
	}
	// the gateway/DNS (never list) is exempt too
	m.SetNever([]netip.Prefix{netip.MustParsePrefix("203.0.113.9/32")})
	for i := 0; i < 20; i++ {
		m.NoteConn("someapp", ap("203.0.113.9:8080"), true)
		clk.Add(30 * time.Second)
	}
	if n, _ := countKind(m, KindBeacon); n != 0 {
		t.Fatal("never-list address flagged")
	}
}

func TestFirstSeenLearnThenReport(t *testing.T) {
	file := filepath.Join(t.TempDir(), "sub", "firstseen.json")
	clk := newClock()
	mk := func() *Manager {
		m := NewManager(nil, WithClock(clk.Now), WithFirstSeenFile(file))
		cfg := DefaultConfig()
		cfg.Enabled = true
		m.Configure(cfg)
		m.SetNetwork("n", ClassUnknown)
		return m
	}
	m := mk()
	// learning phase: silent
	m.NoteConn("firefox", ap("198.51.100.10:443"), true)
	m.NoteConn("firefox", ap("203.0.113.10:443"), true)
	clk.Add(firstSeenLearn + time.Second)
	m.NoteConn("firefox", ap("198.51.100.77:443"), true) // same /24: known
	if n, _ := countKind(m, KindFirstSeen); n != 0 {
		t.Fatalf("learning/known produced %d events", n)
	}
	// a name from the proxy wins over the prefix
	m.Answer("api.sub.example.test", []netip.Addr{mustAddr("192.0.2.50")})
	m.NoteConn("firefox", ap("192.0.2.50:443"), true)
	n, ev := countKind(m, KindFirstSeen)
	if n != 1 || ev.Severity != SevInfo || ev.Detail != "app=firefox target=example.test" {
		t.Fatalf("n=%d ev=%+v", n, ev)
	}
	// again: known now
	m.NoteConn("firefox", ap("192.0.2.50:443"), true)
	// private/loopback/unknown apps are not tracked
	m.NoteConn("firefox", ap("10.1.2.3:80"), true)
	m.NoteConn("", ap("192.0.2.99:80"), true)
	m.NoteConn("uid-1000", ap("192.0.2.98:80"), true)
	// IPv6 is cut to /48
	m.NoteConn("firefox", ap("[2001:db8:1:2::5]:443"), true)
	m.NoteConn("firefox", ap("[2001:db8:1:ffff::9]:443"), true)
	if n, _ := countKind(m, KindFirstSeen); n != 2 {
		t.Fatalf("events %d", n)
	}
	if n, _ := countKind(m, KindFirstSeen); n > 0 {
		for _, e := range m.Events(0).Events {
			if e.Kind == KindFirstSeen && e.Port == 443 && e.Src == "2001:db8:1:ffff::9" {
				t.Fatal("second address of the same /48 reported")
			}
		}
	}
	m.Close() // flushes
	st, err := os.Stat(file)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("file: %v %v", st, err)
	}
	// persisted: a new manager does not report the known ones, not even in the learn window
	m2 := mk()
	defer m2.Close()
	m2.Answer("api.sub.example.test", []netip.Addr{mustAddr("192.0.2.50")})
	m2.NoteConn("firefox", ap("198.51.100.10:443"), true)
	m2.NoteConn("firefox", ap("192.0.2.50:443"), true)
	if n, _ := countKind(m2, KindFirstSeen); n != 0 {
		t.Fatalf("known destinations reported again: %d", n)
	}
}

func TestFirstSeenRateLimitAndCap(t *testing.T) {
	m, clk := enabledManager(t)
	m.NoteConn("app1", ap("198.51.100.1:443"), true)
	clk.Add(firstSeenLearn + time.Second)
	for i := 0; i < 40; i++ {
		m.NoteConn("app1", netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, byte(i), 1}), 443), true)
	}
	if n, _ := countKind(m, KindFirstSeen); n != firstSeenBurst {
		t.Fatalf("rate limit: %d events", n)
	}
	clk.Add(2 * firstSeenPer)
	m.NoteConn("app1", ap("192.0.2.1:443"), true)
	n, ev := countKind(m, KindFirstSeen)
	if n != firstSeenBurst+1 || ev.Detail != "app=app1 target=192.0.2.0/24 more=34" {
		t.Fatalf("n=%d %q", n, ev.Detail)
	}
	// target cap
	for i := 0; i < maxFirstTargets+50; i++ {
		m.NoteConn("app2", netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, byte(i >> 8), byte(i)}), 80), true)
	}
	m.conn.mu.Lock()
	got := len(m.conn.fsApps["app2"].Targets)
	m.conn.mu.Unlock()
	if got > maxFirstTargets {
		t.Fatalf("targets %d", got)
	}
}

func TestFirstSeenOff(t *testing.T) {
	m, clk := enabledManager(t, func(c *Config) { c.Features[FeatFirstSeen] = Feature{} })
	m.NoteConn("a", ap("198.51.100.1:443"), true)
	clk.Add(time.Hour)
	m.NoteConn("a", ap("203.0.113.1:443"), true)
	if n, _ := countKind(m, KindFirstSeen); n != 0 {
		t.Fatal("feature off")
	}
}

// Short connections (a few seconds, reported when they start) every 20-30 s
// are a beacon even though no socket poll could ever see them.
func TestBeaconShortConnectionsFixedPace(t *testing.T) {
	for _, gap := range []time.Duration{20 * time.Second, 25 * time.Second, 30 * time.Second} {
		m, clk := enabledManager(t)
		dst := ap("203.0.113.9:80")
		for i := 0; i < 10; i++ {
			m.NoteConn("", dst, true) // owner unknown: not blocked, still scored
			clk.Add(gap)
		}
		n, ev := countKind(m, KindBeacon)
		if n != 1 || ev.Port != 80 {
			t.Fatalf("gap %s: beacon events %d (%+v)", gap, n, ev)
		}
	}
}

func TestParseConnPacket(t *testing.T) {
	v4 := []byte{0x45, 0, 0, 40, 0, 0, 0x40, 0, 64, 6, 0, 0, 192, 0, 2, 10, 203, 0, 113, 9, 0xc0, 0x01, 0, 80, 0, 0, 0, 0}
	src, dst, ok := ParseConnPacket(v4)
	if !ok || src != ap("192.0.2.10:49153") || dst != ap("203.0.113.9:80") {
		t.Fatal(src, dst, ok)
	}
	v6 := make([]byte, 48)
	v6[0], v6[6] = 0x60, 6
	copy(v6[8:], netip.MustParseAddr("2001:db8::1").AsSlice())
	copy(v6[24:], netip.MustParseAddr("2001:db8::2").AsSlice())
	v6[40], v6[41], v6[42], v6[43] = 0x9c, 0x40, 0x01, 0xbb
	src, dst, ok = ParseConnPacket(v6)
	if !ok || src != ap("[2001:db8::1]:40000") || dst != ap("[2001:db8::2]:443") {
		t.Fatal(src, dst, ok)
	}
	udp := append([]byte(nil), v4...)
	udp[9] = 17
	frag := append([]byte(nil), v4...)
	frag[6], frag[7] = 0, 8
	for name, p := range map[string][]byte{"udp": udp, "fragment": frag, "short": v4[:10], "empty": nil, "v6short": v6[:30]} {
		if _, _, ok := ParseConnPacket(p); ok {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestFirstSeenSkipsOwnApps(t *testing.T) {
	clk := newClock()
	m := NewManager(nil, WithClock(clk.Now))
	defer m.Close()
	cfg := DefaultConfig()
	cfg.Enabled = true
	m.Configure(cfg)
	m.SetNetwork("n", ClassUnknown)
	m.NoteConn("firefox", ap("198.51.100.10:443"), true)
	clk.Add(firstSeenLearn + time.Second)
	m.NoteConn("shuntd", ap("192.0.2.50:443"), true)
	m.NoteConn("Shunt-Desktop", ap("192.0.2.51:443"), true)
	if n, _ := countKind(m, KindFirstSeen); n != 0 {
		t.Fatalf("own app reported: %d", n)
	}
	m.NoteConn("firefox", ap("192.0.2.60:443"), true)
	if n, _ := countKind(m, KindFirstSeen); n != 1 {
		t.Fatalf("other app: %d", n)
	}
}
