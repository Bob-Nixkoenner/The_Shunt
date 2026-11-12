package defense

import (
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// buildHello builds a ClientHello record by hand.
func buildHello(ver uint16, ciphers []uint16, exts [][2]any) []byte {
	var cs []byte
	for _, c := range ciphers {
		cs = binary.BigEndian.AppendUint16(cs, c)
	}
	var eb []byte
	for _, e := range exts {
		eb = binary.BigEndian.AppendUint16(eb, e[0].(uint16))
		d := e[1].([]byte)
		eb = binary.BigEndian.AppendUint16(eb, uint16(len(d)))
		eb = append(eb, d...)
	}
	var h []byte
	h = binary.BigEndian.AppendUint16(h, ver)
	h = append(h, make([]byte, 32)...)
	h = append(h, 0) // session id
	h = binary.BigEndian.AppendUint16(h, uint16(len(cs)))
	h = append(h, cs...)
	h = append(h, 1, 0) // compression
	h = binary.BigEndian.AppendUint16(h, uint16(len(eb)))
	h = append(h, eb...)
	hs := append([]byte{1, byte(len(h) >> 16), byte(len(h) >> 8), byte(len(h))}, h...)
	rec := append([]byte{22, 3, 1}, byte(len(hs)>>8), byte(len(hs)))
	return append(rec, hs...)
}

func TestJA3Spec(t *testing.T) {
	groups := []byte{0, 6, 0x2a, 0x2a, 0, 29, 0, 23} // GREASE, x25519, secp256r1
	rec := buildHello(0x0303,
		[]uint16{0x0a0a, 0x1301, 0xc02b},
		[][2]any{{uint16(0x3a3a), []byte{}}, {uint16(0), []byte{0, 0}}, {uint16(10), groups}, {uint16(11), []byte{1, 0}}, {uint16(0xfafa), []byte{}}})
	str, hash, ok := JA3(rec)
	want := "771,4865-49195,0-10-11,29-23,0"
	if !ok || str != want {
		t.Fatalf("got %q ok=%v", str, ok)
	}
	sum := md5.Sum([]byte(want))
	if hash != hex.EncodeToString(sum[:]) {
		t.Fatal("hash")
	}
	// no extensions: spec example shape
	str, _, ok = JA3(buildHello(769, []uint16{4, 5, 10}, nil))
	if !ok || str != "769,4-5-10,,," {
		t.Fatalf("no ext: %q", str)
	}
}

func TestJA3Garbage(t *testing.T) {
	good := buildHello(0x0303, []uint16{0x1301}, [][2]any{{uint16(10), []byte{0, 2, 0, 29}}})
	for n := 0; n < len(good)-1; n++ { // every cut-off prefix must not panic
		JA3(good[:n])
	}
	for _, b := range [][]byte{nil, {22}, {23, 3, 3, 0, 5, 1, 0, 0, 1, 0}, []byte(strings.Repeat("A", 50))} {
		if _, _, ok := JA3(b); ok {
			t.Fatalf("accepted %v", b)
		}
	}
}

// A real Go client hello must parse and be stable.
func TestJA3RealClient(t *testing.T) {
	a, b := net.Pipe()
	go func() {
		c := tls.Client(a, &tls.Config{ServerName: "example.invalid", InsecureSkipVerify: true})
		_ = a.SetDeadline(time.Now().Add(time.Second))
		_ = c.Handshake()
	}()
	buf := make([]byte, 4096)
	_ = b.SetReadDeadline(time.Now().Add(time.Second))
	n, _ := b.Read(buf)
	b.Close()
	str, hash, ok := JA3(buf[:n])
	if !ok || len(hash) != 32 || !strings.HasPrefix(str, "771,") {
		t.Fatalf("%q %q %v", str, hash, ok)
	}
}

func TestParseJA3ListAndUpdater(t *testing.T) {
	const bad = "b386946a5a44d1ddcc843bc75336dfce"
	body := "# header\n#\n# ja3_md5,Firstseen,Lastseen,Listingreason\n" + bad + ",2017-07-14 18:08:15,2019-07-27 20:42:54,Dridex\nnot-a-hash,x\nZZ6946a5a44d1ddcc843bc75336dfce\n"
	if got := ParseJA3List(strings.NewReader(body)); len(got) != 1 {
		t.Fatalf("%v", got)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, body) }))
	defer srv.Close()
	r := NewReputation()
	u := &Updater{Rep: r, Dir: t.TempDir()}
	if err := u.Refresh(context.Background(), []Source{{Name: "sslbl_ja3", URL: srv.URL, TTL: time.Hour, JA3: true}}); err != nil {
		t.Fatal(err)
	}
	if n, ok := r.LookupJA3(strings.ToUpper(bad)); !ok || n != "sslbl_ja3" {
		t.Fatal("lookup")
	}
	clk := newClock()
	r.now = clk.Now
	r.SetJA3List("x", map[string]struct{}{bad: {}}, clk.Now().Add(time.Hour))
	r.SetJA3List("sslbl_ja3", nil, time.Time{})
	clk.Add(2 * time.Hour)
	if _, ok := r.LookupJA3(bad); ok {
		t.Fatal("expired list used")
	}
	r.Prune()
	if len(r.ja3) != 1 { // only the never-expiring (empty) one stays
		t.Fatalf("prune: %d", len(r.ja3))
	}
}

func TestSourcesForOptional(t *testing.T) {
	if n := len(SourcesFor(nil, nil)); n != len(DefaultSources) {
		t.Fatalf("default must have no optional lists: %d", n)
	}
	got := SourcesFor([]string{"sslbl_ja3", "et_compromised", "et_compromised", "bogus"}, nil)
	if len(got) != len(DefaultSources)+2 {
		t.Fatalf("%+v", got)
	}
}

func TestManagerJA3Hit(t *testing.T) {
	pm := &portMap{real: map[int]int{}}
	banCh := make(chan Ban, 4)
	m, _ := newTestManager(t, pm, banCh)
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.DecoyPorts = []int{443}
	cfg.Features[FeatReputation] = Feature{Watch: true, Block: true}
	m.Configure(cfg)
	m.SetNetwork("k", ClassUnknown)
	hello := buildHello(0x0303, []uint16{0x1301}, [][2]any{{uint16(10), []byte{0, 2, 0, 29}}})
	_, h, _ := JA3(hello)
	for i := 0; i < 2; i++ {
		c := pm.dial(t, 443)
		c.Write(hello)
		time.Sleep(150 * time.Millisecond)
		c.Close()
		if i == 0 {
			m.Reputation().SetJA3List("sslbl_ja3", map[string]struct{}{h: {}}, time.Time{})
		}
	}
	var seenInfo, seenBad bool
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && !(seenInfo && seenBad) {
		for _, e := range m.Events(0).Events {
			if e.Kind == KindObservation && e.Detail == "ja3="+h {
				seenInfo = true
			}
			if e.Kind == KindReputation && e.Severity == SevHigh && e.Detail == "list=sslbl_ja3 ja3="+h {
				seenBad = true
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !seenInfo || !seenBad {
		t.Fatalf("info=%v bad=%v %+v", seenInfo, seenBad, m.Events(0).Events)
	}
}

func TestSourcesForOff(t *testing.T) {
	got := SourcesFor(nil, []string{"feodo"})
	if len(got) != 1 || got[0].Name != "sslbl" {
		t.Fatalf("%+v", got)
	}
	if n := len(SourcesFor(nil, []string{"feodo", "sslbl"})); n != 0 {
		t.Fatal(n)
	}
}

func TestQualityListOnly(t *testing.T) {
	for _, n := range []string{"feodo", "sslbl", "sslbl_ja3", SpamhausDROP} {
		if !QualityList(n) {
			t.Fatal(n)
		}
	}
	if QualityList("et_compromised") || QualityList("x") {
		t.Fatal("false-alarm list may not block")
	}
	if _, ok := OptionalSources[SpamhausDROP]; ok {
		t.Fatal("spamhaus must not be built in")
	}
}

// A hit on a report-only list is reported with its name but never blocks.
func TestReportOnlyListDoesNotBan(t *testing.T) {
	pm := &portMap{real: map[int]int{}}
	m, _ := newTestManager(t, pm, make(chan Ban, 4))
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Features[FeatReputation] = Feature{Watch: true, Block: true}
	m.Configure(cfg)
	m.SetNetwork("k", ClassUnknown)
	m.Reputation().SetList("et_compromised", ParseList(strings.NewReader("192.0.2.9\n")), time.Time{})
	m.Reputation().SetList("feodo", ParseList(strings.NewReader("192.0.2.10\n")), time.Time{})
	m.CheckPeer(netip.MustParseAddr("192.0.2.9"), 0, "tcp")
	m.CheckPeer(netip.MustParseAddr("192.0.2.10"), 0, "tcp")
	var det []string
	for _, e := range m.Events(0).Events {
		if e.Kind == KindReputation {
			det = append(det, e.Src+" "+e.Detail)
		}
	}
	if len(det) != 2 || det[0] != "192.0.2.9 list=et_compromised" {
		t.Fatalf("%v", det)
	}
	for _, b := range m.Status().Bans {
		if b.Src == "192.0.2.9" {
			t.Fatal("report-only list banned")
		}
	}
}

func TestSourceStatusAndExpiry(t *testing.T) {
	ok := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !ok {
			http.Error(w, "no", 503)
			return
		}
		if r.UserAgent() != "the-shunt" {
			t.Errorf("user agent %q", r.UserAgent())
		}
		io.WriteString(w, "192.0.2.1\n192.0.2.2\n")
	}))
	defer srv.Close()
	dir := t.TempDir()
	r := NewReputation()
	u := &Updater{Rep: r, Dir: dir}
	s := Source{Name: "feodo", URL: srv.URL, TTL: time.Hour}
	if err := u.Refresh(context.Background(), []Source{s}); err != nil {
		t.Fatal(err)
	}
	if st := r.Stat("feodo"); st.Entries != 2 || st.Updated.IsZero() || st.Error != "" {
		t.Fatalf("%+v", st)
	}
	ok = false
	// the download keeps failing and the cached list is older than its TTL
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(filepath.Join(dir, "rep-feodo.txt"), old, old); err != nil {
		t.Fatal(err)
	}
	if err := u.Refresh(context.Background(), []Source{s}); err == nil {
		t.Fatal("want error")
	}
	if st := r.Stat("feodo"); st.Error == "" {
		t.Fatalf("%+v", st)
	}
	if _, hit := r.Lookup(netip.MustParseAddr("192.0.2.1")); hit {
		t.Fatal("expired list still matches")
	}
}

func TestSourceInfoExpired(t *testing.T) {
	pm := &portMap{real: map[int]int{}}
	m, _ := newTestManager(t, pm, make(chan Ban, 1))
	now := m.Reputation().now()
	m.Reputation().SetStat("feodo", SourceStat{Entries: 3, Updated: now.Add(-100 * time.Hour)})
	m.Reputation().SetStat("sslbl", SourceStat{Entries: 3, Updated: now.Add(-time.Hour)})
	var feodo, sslbl, drop SourceInfo
	for _, s := range m.Status().Sources {
		switch s.Name {
		case "feodo":
			feodo = s
		case "sslbl":
			sslbl = s
		case SpamhausDROP:
			drop = s
		}
	}
	if !feodo.On || !feodo.Expired || sslbl.Expired || !drop.Unavailable || drop.On {
		t.Fatalf("%+v %+v %+v", feodo, sslbl, drop)
	}
}

// A record whose length field is shorter than the handshake header must not
// panic (one short packet to the TLS decoy used to crash the daemon).
func TestJA3ShortRecordLength(t *testing.T) {
	for _, rec := range [][]byte{
		{22, 3, 1, 0, 0, 0, 0, 0, 0, 0, 0},
		{22, 3, 1, 0, 1, 1, 0, 0, 0, 0, 0},
		{22, 3, 1, 0, 3, 1, 0, 0, 0, 0, 0},
	} {
		if _, _, ok := JA3(rec); ok {
			t.Fatalf("% x: accepted", rec)
		}
	}
}

func FuzzJA3(f *testing.F) {
	f.Add([]byte{22, 3, 1, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{22, 3, 1, 0, 4, 1, 0, 0, 0})
	for _, h := range ja3Seeds() {
		f.Add(h)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		s, h, ok := JA3(b)
		if ok && (len(h) != 32 || s == "") {
			t.Fatalf("ok with str=%q hash=%q", s, h)
		}
	})
}

func ja3Seeds() [][]byte {
	return [][]byte{
		buildHello(0x0303, []uint16{0x1301, 0x0a0a}, [][2]any{{uint16(10), []byte{0, 4, 0, 29, 0x1a, 0x1a}}, {uint16(11), []byte{1, 0}}}),
		buildHello(0x0301, nil, nil),
	}
}
