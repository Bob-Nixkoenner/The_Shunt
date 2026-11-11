package defense

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock { return &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)} }
func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *fakeClock) Add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestRing(t *testing.T) {
	r := NewRing(300)
	for i := 0; i < 250; i++ {
		r.Add(Event{Kind: KindScan})
	}
	for _, tc := range []struct {
		since uint64
		n     int
		first uint64
	}{{0, 200, 1}, {200, 50, 201}, {250, 0, 0}, {900, 0, 0}} {
		got := r.Events(tc.since)
		if len(got.Events) != tc.n || got.LastSeq != 250 {
			t.Fatalf("since %d: n=%d last=%d", tc.since, len(got.Events), got.LastSeq)
		}
		if tc.n > 0 && got.Events[0].Seq != tc.first {
			t.Fatalf("first seq %d", got.Events[0].Seq)
		}
	}
	small := NewRing(3)
	for i := 0; i < 5; i++ {
		small.Add(Event{})
	}
	if e := small.Events(0).Events; len(e) != 3 || e[0].Seq != 3 {
		t.Fatalf("overflow: %+v", e)
	}
}

func TestRingConcurrent(t *testing.T) {
	r := NewRing(50)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				r.Add(Event{})
				r.Events(0)
			}
		}()
	}
	wg.Wait()
	if r.LastSeq() != 1600 {
		t.Fatal(r.LastSeq())
	}
}

func TestThermo(t *testing.T) {
	clk := newClock()
	for _, tc := range []struct {
		class    Class
		min, max int
	}{{ClassPublic, 85, 100}, {ClassManaged, 70, 90}, {ClassTrusted, 50, 75}} {
		th := NewThermo()
		th.now = clk.Now
		th.SetNetwork("n", tc.class)
		for i := 0; i < 5; i++ {
			th.Add(Event{Kind: KindScan, Severity: SevHigh})
		}
		if h := th.Heat(); h < tc.min || h > tc.max {
			t.Errorf("%s: heat %d not in %d..%d", tc.class, h, tc.min, tc.max)
		}
	}
	th := NewThermo()
	th.now = clk.Now
	th.SetNetwork("a", ClassPublic)
	for i := 0; i < 3; i++ {
		th.Add(Event{Kind: KindScan, Severity: SevHigh})
	}
	h0 := th.Heat()
	clk.Add(HeatHalfLife)
	h1 := th.Heat()
	if h1 >= h0 || h1 < 20 {
		t.Errorf("decay %d -> %d", h0, h1)
	}
	clk.Add(10 * time.Hour)
	if th.Heat() != 0 {
		t.Error("should cool to 0")
	}
	for i := 0; i < 1000; i++ {
		th.Add(Event{Kind: KindARP, Severity: SevHigh})
	}
	if th.Heat() != 100 {
		t.Errorf("saturation %d", th.Heat())
	}
	th.Add(Event{Kind: KindBan, Severity: SevHigh})
	if th.Counts()[KindScan] != 3 {
		t.Error(th.Counts())
	}
	th.SetNetwork("a", ClassPublic) // same key: keep
	if th.Counts()[KindScan] != 3 {
		t.Error("same key must keep counters")
	}
	th.SetNetwork("b", ClassPublic)
	if len(th.Counts()) != 0 {
		t.Error("new key must reset counters")
	}
}

func TestDetectorScanBrute(t *testing.T) {
	clk := newClock()
	never := &NeverSet{}
	never.SetConfig(ParsePrefixes([]string{"198.51.100.0/24"}))
	never.SetAuto(ParsePrefixes([]string{"203.0.113.1"}))
	d := NewDetector(DetectConfig{ScanPorts: 5, BruteConns: 4}, never)
	d.now = clk.Now
	var got []Finding
	d.OnFound = func(f Finding) { got = append(got, f) }

	for p := 1; p <= 4; p++ {
		d.Observe(mustAddr("192.0.2.1"), p, "tcp", true)
	}
	if len(got) != 0 {
		t.Fatal("below threshold")
	}
	d.Observe(mustAddr("192.0.2.1"), 5, "tcp", true)
	if len(got) != 1 || got[0].Kind != KindScan {
		t.Fatalf("scan: %+v", got)
	}
	d.Observe(mustAddr("192.0.2.1"), 6, "tcp", true) // no repeat inside window
	if len(got) != 1 {
		t.Fatal("repeat")
	}
	clk.Add(2 * time.Minute)
	for i := 0; i < 4; i++ {
		d.Observe(mustAddr("192.0.2.2"), 22, "tcp", false)
	}
	if len(got) != 2 || got[1].Kind != KindBruteForce || got[1].Src != mustAddr("192.0.2.2") {
		t.Fatalf("brute: %+v", got)
	}
	// slow probing stays below threshold
	for i := 0; i < 10; i++ {
		clk.Add(30 * time.Second)
		d.Observe(mustAddr("192.0.2.3"), 1000+i, "tcp", true)
	}
	if len(got) != 2 {
		t.Fatal("slow scan flagged")
	}
	for _, s := range []string{"198.51.100.7", "203.0.113.1"} {
		for p := 1; p <= 20; p++ {
			d.Observe(mustAddr(s), p, "tcp", false)
		}
	}
	if len(got) != 2 {
		t.Fatalf("never-list ignored: %+v", got)
	}
	// IPv6 and mapped
	for p := 1; p <= 5; p++ {
		d.Observe(mustAddr("::ffff:192.0.2.9"), p, "tcp", true)
	}
	if len(got) != 3 || got[2].Src != mustAddr("192.0.2.9") {
		t.Fatalf("mapped: %+v", got)
	}
}

func TestDetectorMemoryCap(t *testing.T) {
	d := NewDetector(DetectConfig{MaxSources: 3}, nil)
	for i := 1; i <= 10; i++ {
		d.Observe(netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}), 1, "tcp", true)
	}
	if len(d.src) > 3 {
		t.Fatal(len(d.src))
	}
}

func TestBeaconScore(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mk := func(gaps ...float64) []time.Time {
		ts := []time.Time{base}
		for _, g := range gaps {
			ts = append(ts, ts[len(ts)-1].Add(time.Duration(g*float64(time.Second))))
		}
		return ts
	}
	for _, tc := range []struct {
		name     string
		ts       []time.Time
		min, max float64
	}{
		{"clockwork", mk(60, 60, 60, 60, 60, 60), 0.95, 1},
		{"light jitter", mk(60, 62, 59, 61, 60, 58), 0.7, 1},
		{"irregular", mk(5, 300, 20, 2, 90, 700), 0, 0.2},
		{"too few", mk(60, 60), 0, 0},
		{"too fast", mk(0.1, 0.1, 0.1, 0.1, 0.1, 0.1), 0, 0},
	} {
		s, _ := BeaconScore(tc.ts, 5)
		if s < tc.min || s > tc.max {
			t.Errorf("%s: %.2f", tc.name, s)
		}
	}
	if _, iv := BeaconScore(mk(60, 60, 60, 60, 60), 5); iv != time.Minute {
		t.Error(iv)
	}
	bt := NewBeaconTracker()
	var s float64
	for i := 0; i < 8; i++ {
		s, _ = bt.Add("192.0.2.5:443", base.Add(time.Duration(i)*30*time.Second), 5)
	}
	if s < 0.95 {
		t.Error(s)
	}
	bt.MaxTargets = 1
	if s, _ := bt.Add("other", base, 5); s != 0 {
		t.Error("cap")
	}
}

func TestDNSTunnelScore(t *testing.T) {
	normal := []DNSQuery{{"www.example.com", "A"}, {"mail.example.org", "A"}, {"cdn.example.net", "AAAA"},
		{"api.example.com", "A"}, {"example.com", "A"}, {"static.example.com", "A"}}
	tun := []DNSQuery{}
	for _, l := range []string{"a9f3k2j8d7h1g5s0q4w6e8r2t7y1u3i9o5p0z", "x7c2v5b8n1m4q9w3e6r0t2y5u8i1o4p7a3s6d", "k1j4h7g0f3d6s9a2p5o8i1u4y7t0r3e6w9q2",
		"m3n6b9v2c5x8z1l4k7j0h3g6f9d2s5a8p1o4", "z8x5c2v9b6n3m0l7k4j1h8g5f2d9s6a3p0o7"} {
		tun = append(tun, DNSQuery{l + ".t.example.com", "TXT"})
	}
	if s := DNSTunnelScore(normal); s > 0.1 {
		t.Errorf("normal %.2f", s)
	}
	if s := DNSTunnelScore(tun); s < 0.8 {
		t.Errorf("tunnel %.2f", s)
	}
	if DNSTunnelScore(tun[:3]) != 0 {
		t.Error("few queries")
	}
}

func TestParseListAndLookup(t *testing.T) {
	in := "# c\n\n192.0.2.1\n198.51.100.0/24 # x\n203.0.113.5,botnet,2026\n\"192.0.2.77\";x\nnot-an-ip\n2001:db8::/32\n::ffff:192.0.2.200\n"
	p := ParseList(strings.NewReader(in))
	if len(p) != 6 {
		t.Fatalf("parsed %d: %v", len(p), p)
	}
	clk := newClock()
	r := NewReputation()
	r.now = clk.Now
	r.SetList("a", p, clk.Now().Add(time.Hour))
	for s, want := range map[string]bool{"192.0.2.1": true, "198.51.100.99": true, "203.0.113.5": true, "192.0.2.77": true,
		"2001:db8:1::1": true, "192.0.2.200": true, "192.0.2.2": false, "203.0.113.6": false, "2001:dead::1": false} {
		if _, ok := r.Lookup(mustAddr(s)); ok != want {
			t.Errorf("%s: %v", s, ok)
		}
	}
	clk.Add(2 * time.Hour)
	if _, ok := r.Lookup(mustAddr("192.0.2.1")); ok {
		t.Error("expired")
	}
	r.Prune()
	if len(r.lists) != 0 {
		t.Error("prune")
	}
}

func TestExampleList(t *testing.T) {
	r := NewReputation()
	r.SetList("example", ParseList(strings.NewReader(ExampleList())), time.Time{})
	for _, s := range []string{"192.0.2.66", "198.51.100.3", "203.0.113.200", "2001:db8:bad::5"} {
		if _, ok := r.Lookup(mustAddr(s)); !ok {
			t.Errorf("%s missing", s)
		}
	}
}

func TestUpdaterCache(t *testing.T) {
	fail := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if fail {
			http.Error(w, "x", 503)
			return
		}
		io.WriteString(w, "192.0.2.10\n")
	}))
	defer srv.Close()
	dir := t.TempDir()
	r := NewReputation()
	u := &Updater{Rep: r, Dir: filepath.Join(dir, "c")}
	src := []Source{{Name: "t", URL: srv.URL, TTL: time.Hour}}
	if err := u.Refresh(context.Background(), src); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Lookup(mustAddr("192.0.2.10")); !ok {
		t.Fatal("not loaded")
	}
	fail = true
	r2 := NewReputation()
	u2 := &Updater{Rep: r2, Dir: u.Dir}
	if err := u2.Refresh(context.Background(), src); err == nil {
		t.Error("want error")
	}
	if _, ok := r2.Lookup(mustAddr("192.0.2.10")); !ok {
		t.Error("cache fallback failed")
	}
	// stale cache: expired by file age
	old := time.Now().Add(-3 * time.Hour)
	os.Chtimes(filepath.Join(u.Dir, "rep-t.txt"), old, old)
	r3 := NewReputation()
	(&Updater{Rep: r3, Dir: u.Dir}).Refresh(context.Background(), src)
	if _, ok := r3.Lookup(mustAddr("192.0.2.10")); ok {
		t.Error("stale cache must be expired")
	}
}

func TestBans(t *testing.T) {
	clk := newClock()
	b := NewBans()
	b.now = clk.Now
	var on, off []string
	b.OnBan = func(x Ban) { on = append(on, x.Src) }
	b.OnUnban = func(x Ban) { off = append(off, x.Src) }
	if _, isNew := b.Add("192.0.2.1", KindScan, time.Minute); !isNew {
		t.Fatal()
	}
	if _, isNew := b.Add("192.0.2.1", KindScan, time.Hour); isNew {
		t.Fatal("dup")
	}
	b.Add("192.0.2.2", KindBruteForce, time.Minute)
	if len(on) != 2 || !b.Has("192.0.2.2") {
		t.Fatal(on)
	}
	clk.Add(2 * time.Minute)
	if b.Has("192.0.2.2") || !b.Has("192.0.2.1") {
		t.Fatal("expiry/extend")
	}
	if g := b.Prune(); len(g) != 1 || g[0].Src != "192.0.2.2" {
		t.Fatal(g)
	}
	b.Add("192.0.2.3", KindScan, time.Hour)
	b.Remove("192.0.2.3")
	if len(b.List()) != 1 {
		t.Fatal(b.List())
	}
	b.Remove("")
	if len(b.List()) != 0 || len(off) != 3 {
		t.Fatal(off)
	}
}

// listenLocal opens decoys on free loopback ports; port numbers are mapped
// so tests never need privileges.
type portMap struct {
	mu    sync.Mutex
	real  map[int]int
	taken map[int]bool
}

func (p *portMap) listen(port int) (net.Listener, error) {
	if p.taken[port] {
		return nil, errors.New("address already in use")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err == nil {
		p.mu.Lock()
		p.real[port] = ln.Addr().(*net.TCPAddr).Port
		p.mu.Unlock()
	}
	return ln, err
}

func (p *portMap) dial(t *testing.T, port int) net.Conn {
	t.Helper()
	p.mu.Lock()
	rp := p.real[port]
	p.mu.Unlock()
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(rp)), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	return c
}

func waitFor(t *testing.T, what string, f func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if f() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timeout: %s", what)
}

func TestDecoysSkipAndBanner(t *testing.T) {
	pm := &portMap{real: map[int]int{}, taken: map[int]bool{80: true}}
	var mu sync.Mutex
	var hits []Hit
	d := NewDecoys(pm.listen, func(h Hit) { mu.Lock(); hits = append(hits, h); mu.Unlock() })
	d.Start([]int{22, 80, 443}, DecoyOptions{})
	defer d.Stop()
	if got := d.Ports(); len(got) != 2 || got[0] != 22 || got[1] != 443 {
		t.Fatalf("ports %v", got)
	}
	if _, ok := d.Skipped()[80]; !ok {
		t.Fatal("80 not remembered")
	}
	c := pm.dial(t, 22)
	line, _ := bufio.NewReader(c).ReadString('\n')
	c.Close()
	if !strings.HasPrefix(line, "SSH-2.0-OpenSSH_9.6") {
		t.Fatalf("banner %q", line)
	}
	waitFor(t, "hit", func() bool { mu.Lock(); defer mu.Unlock(); return len(hits) == 1 })
	if hits[0].Kind != KindDecoyHit || hits[0].Port != 22 || !hits[0].Src.IsLoopback() {
		t.Fatalf("%+v", hits[0])
	}
	d.Start(nil, DecoyOptions{})
	if len(d.Ports()) != 0 {
		t.Fatal("restart with none")
	}
}

func TestTarpit(t *testing.T) {
	pm := &portMap{real: map[int]int{}}
	var mu sync.Mutex
	var kinds []Kind
	d := NewDecoys(pm.listen, func(h Hit) { mu.Lock(); kinds = append(kinds, h.Kind); mu.Unlock() })
	d.Tarpit = &Tarpit{Interval: 20 * time.Millisecond, MaxHold: 200 * time.Millisecond, MaxConns: 1}
	d.Start([]int{22}, DecoyOptions{Tarpit: true})
	defer d.Stop()
	c1 := pm.dial(t, 22)
	defer c1.Close()
	r := bufio.NewReader(c1)
	r.ReadString('\n') // banner
	b, err := r.ReadByte()
	if err != nil || b != 'x' {
		t.Fatalf("drip %v %v", b, err)
	}
	waitFor(t, "active", func() bool { return d.Tarpit.Active() == 1 })
	// second connection: no slot -> not held, closed after banner
	c2 := pm.dial(t, 22)
	defer c2.Close()
	if _, err := io.ReadAll(c2); err != nil {
		t.Fatalf("second should close: %v", err)
	}
	// max hold ends the first
	waitFor(t, "release", func() bool { return d.Tarpit.Active() == 0 })
	mu.Lock()
	defer mu.Unlock()
	found := false
	for _, k := range kinds {
		found = found || k == KindTarpit
	}
	if !found {
		t.Fatalf("no tarpit event: %v", kinds)
	}
}

func TestCowrieTelnet(t *testing.T) {
	pm := &portMap{real: map[int]int{}}
	var mu sync.Mutex
	var hits []Hit
	d := NewDecoys(pm.listen, func(h Hit) { mu.Lock(); hits = append(hits, h); mu.Unlock() })
	d.Start([]int{23, 22}, DecoyOptions{Cowrie: true})
	defer d.Stop()
	c := pm.dial(t, 23)
	io.WriteString(c, "root\r\nhunter2secret\r\n")
	all, _ := io.ReadAll(bufio.NewReader(c)) // closes after 3 tries or EOF
	c.Close()
	if !strings.Contains(string(all), "login: ") {
		t.Fatalf("%q", all)
	}
	waitFor(t, "cowrie", func() bool {
		mu.Lock()
		defer mu.Unlock()
		for _, h := range hits {
			if h.Kind == KindCowrie {
				return true
			}
		}
		return false
	})
	mu.Lock()
	defer mu.Unlock()
	for _, h := range hits {
		if strings.Contains(h.Detail, "hunter2secret") {
			t.Fatal("password stored")
		}
		if h.Kind == KindCowrie && (!strings.Contains(h.Detail, "user=root") || !strings.Contains(h.Detail, "len=13")) {
			t.Fatalf("detail %q", h.Detail)
		}
	}
	// ssh banner variant
	mu.Unlock()
	c2 := pm.dial(t, 22)
	io.WriteString(c2, "SSH-2.0-libssh_0.9\r\n")
	io.ReadAll(c2)
	c2.Close()
	waitFor(t, "ssh cowrie", func() bool {
		mu.Lock()
		defer mu.Unlock()
		for _, h := range hits {
			if h.Kind == KindCowrie && strings.Contains(h.Detail, "libssh") {
				return true
			}
		}
		return false
	})
	mu.Lock()
}

func TestPasswordDigest(t *testing.T) {
	a, b := PasswordDigest("abc"), PasswordDigest("abd")
	if a == b || !strings.HasPrefix(a, "len=3 h=") || len(a) != len("len=3 h=")+8 {
		t.Fatal(a, b)
	}
}

func newTestManager(t *testing.T, pm *portMap, ban chan Ban) (*Manager, *fakeClock) {
	t.Helper()
	clk := newClock()
	opts := []Option{WithListen(pm.listen), WithClock(clk.Now)}
	if ban != nil {
		opts = append(opts, WithBanHooks(func(b Ban) { ban <- b }, nil))
	}
	m := NewManager(slog.New(slog.NewTextHandler(io.Discard, nil)), opts...)
	t.Cleanup(m.Close)
	return m, clk
}

func TestManagerDecoysByClass(t *testing.T) {
	pm := &portMap{real: map[int]int{}, taken: map[int]bool{445: true}}
	m, _ := newTestManager(t, pm, nil)
	cfg := DefaultConfig()
	cfg.Enabled = true
	m.Configure(cfg)
	m.SetNetwork("net1", ClassTrusted)
	if len(m.Status().Decoys) != 0 {
		t.Fatal("trusted must have no decoys")
	}
	m.SetNetwork("net2", ClassPublic)
	st := m.Status()
	if len(st.Decoys) != 5 { // 445 taken
		t.Fatalf("decoys %v", st.Decoys)
	}
	m.SetNetwork("net3", ClassManaged)
	if len(m.Status().Decoys) != 0 {
		t.Fatal("managed: no decoys")
	}
	m.SetNetwork("net4", "weird") // normalised to public
	if m.Status().Class != ClassPublic || len(m.Status().Decoys) == 0 {
		t.Fatal("unknown class must act public")
	}
	f := cfg.Features
	f[FeatDecoy] = Feature{}
	m.Configure(cfg)
	if len(m.Status().Decoys) != 0 {
		t.Fatal("feature off")
	}
}

func TestManagerHitToBanAndHeat(t *testing.T) {
	pm := &portMap{real: map[int]int{}}
	banCh := make(chan Ban, 4)
	m, _ := newTestManager(t, pm, banCh)
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.DecoyPorts = []int{21, 22, 25, 80, 443, 3389, 8080}
	cfg.Features[FeatScan] = Feature{Watch: true, Block: true}
	m.Configure(cfg)
	m.SetNetwork("k", ClassPublic)
	for _, p := range cfg.DecoyPorts {
		c := pm.dial(t, p)
		c.Close()
	}
	select {
	case b := <-banCh:
		if b.Src != "127.0.0.1" || b.Reason != KindScan {
			t.Fatalf("%+v", b)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no ban")
	}
	st := m.Status()
	if st.Heat < 25 || st.Counts[KindScan] != 1 || st.Counts[KindDecoyHit] < 6 || len(st.Bans) != 1 {
		t.Fatalf("%+v", st)
	}
	ev := m.Events(0)
	if ev.Events[0].Kind != KindNetEnter || ev.Events[0].Seq != 1 {
		t.Fatalf("%+v", ev.Events[0])
	}
	m.Unban("")
	if len(m.Status().Bans) != 0 {
		t.Fatal("unban")
	}
}

func TestManagerNeverAndBlockSwitch(t *testing.T) {
	pm := &portMap{real: map[int]int{}}
	banCh := make(chan Ban, 4)
	m, _ := newTestManager(t, pm, banCh)
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Never = []string{"192.0.2.0/24"}
	cfg.Features[FeatReputation] = Feature{Watch: true, Block: true}
	m.Configure(cfg)
	m.Reputation().SetList("x", ParseList(strings.NewReader("192.0.2.5\n198.51.100.5\n")), time.Time{})
	m.SetNever(ParsePrefixes([]string{"2001:db8::1"}))
	m.Observe(mustAddr("192.0.2.5"), 1, "tcp", true) // never-listed: reported but not banned
	m.Observe(mustAddr("198.51.100.5"), 1, "tcp", true)
	m.Observe(mustAddr("198.51.100.6"), 1, "tcp", true) // clean
	b := <-banCh
	if b.Src != "198.51.100.5" {
		t.Fatalf("%+v", b)
	}
	if m.Status().Counts[KindReputation] != 2 || len(m.Status().Bans) != 1 {
		t.Fatalf("%+v", m.Status())
	}
	// Block without Watch must do nothing
	cfg.Features[FeatReputation] = Feature{Block: true}
	m.Configure(cfg)
	m.Unban("")
	m.Observe(mustAddr("198.51.100.5"), 1, "tcp", true)
	if len(m.Status().Bans) != 0 {
		t.Fatal("block without watch")
	}
}

func TestManagerDisabled(t *testing.T) {
	pm := &portMap{real: map[int]int{}}
	m, _ := newTestManager(t, pm, nil)
	m.SetNetwork("k", ClassPublic)
	m.Report(Event{Kind: KindScan, Severity: SevHigh})
	st := m.Status()
	if st.Enabled || st.Heat != 0 || len(st.Decoys) != 0 || st.LastSeq != 0 {
		t.Fatalf("%+v", st)
	}
	if st.Decoys == nil || st.Bans == nil {
		t.Fatal("slices must not be nil")
	}
}

func TestManagerBanExpiry(t *testing.T) {
	pm := &portMap{real: map[int]int{}}
	m, clk := newTestManager(t, pm, nil)
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.BanSeconds = 60
	cfg.Features[FeatBrute] = Feature{Watch: true, Block: true}
	m.Configure(cfg)
	for i := 0; i < 10; i++ {
		m.Observe(mustAddr("203.0.113.9"), 22, "tcp", false)
	}
	if len(m.Status().Bans) != 1 {
		t.Fatal("not banned")
	}
	clk.Add(2 * time.Minute)
	m.bans.Prune()
	if len(m.Status().Bans) != 0 {
		t.Fatal("not expired")
	}
}

func TestManagerCloseTwiceAndRace(t *testing.T) {
	pm := &portMap{real: map[int]int{}}
	m, _ := newTestManager(t, pm, nil)
	cfg := DefaultConfig()
	cfg.Enabled = true
	m.Configure(cfg)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				m.SetNetwork("n"+itoa(j%3), ClassPublic)
				m.Configure(cfg)
				m.Status()
				m.Report(Event{Kind: KindObservation})
				if c, err := net.DialTimeout("tcp", "127.0.0.1:1", 10*time.Millisecond); err == nil {
					c.Close()
				}
			}
		}(i)
	}
	wg.Wait()
	m.Close()
	m.Close()
}
