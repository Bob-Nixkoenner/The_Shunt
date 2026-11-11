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
	if n := len(SourcesFor(nil)); n != len(DefaultSources) {
		t.Fatalf("default must have no optional lists: %d", n)
	}
	got := SourcesFor([]string{"sslbl_ja3", "et_compromised", "et_compromised", "bogus"})
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
	m.SetNetwork("k", ClassPublic)
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
