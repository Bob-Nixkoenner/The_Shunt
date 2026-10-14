package blocklist

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
)

const sample = `# comment
! adblock comment
||ads.example.com^
||tracker.example^$important
||only-third-party.example^$third-party
0.0.0.0 exact.example.org
127.0.0.1 localhost
plain.example.net
@@||allowed.example^
example.com/path
||UPPER.Example.COM^
` + "||" + "x" + `^
`

func TestParseAndHas(t *testing.T) {
	l, err := Parse("t", strings.NewReader(sample+strings.Repeat("a", MaxLine*2)+"\n||after-long.example^\n"))
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]bool{
		"ads.example.com": true, "a.b.ads.example.com": true, "xads.example.com": false, "example.com": false,
		"tracker.example": true, "only-third-party.example": false,
		"exact.example.org": true, "sub.exact.example.org": false,
		"plain.example.net": true, "allowed.example": false, "localhost": false,
		"upper.example.com": true, "after-long.example": true,
	} {
		if got := l.Has(name); got != want {
			t.Errorf("%s: got %v", name, got)
		}
	}
}

func TestParseRejectsNonLists(t *testing.T) {
	if _, err := Parse("t", strings.NewReader("<html><body>404</body></html>\n")); err != ErrEmpty {
		t.Fatalf("got %v", err)
	}
}

func TestFilterLevelsAndAllow(t *testing.T) {
	ads, _ := Parse("ads", strings.NewReader("||ads.example^\n"))
	mal, _ := Parse("mal", strings.NewReader("||evil.example^\n"))
	f := NewFilter(map[string][]*List{"normal": {ads}, "paranoid": {ads, mal}}, []string{"ok.ads.example"})
	cases := []struct{ level, name, want string }{
		{"normal", "x.ads.example", "ads"},
		{"normal", "evil.example", ""},
		{"paranoid", "evil.example", "mal"},
		{"low", "x.ads.example", ""},
		{"off", "x.ads.example", ""},
		{"paranoid", "ok.ads.example", ""},
		{"paranoid", "a.ok.ads.example", ""},
	}
	for _, c := range cases {
		if got := f.Check(c.level, c.name); got != c.want {
			t.Errorf("%s %s: got %q", c.level, c.name, got)
		}
	}
	if (*Filter)(nil).Check("normal", "x.ads.example") != "" {
		t.Error("nil filter blocks")
	}
}

// Lists of unused levels are never fetched; a fresh cache is not fetched
// again; a not-modified answer keeps the list.
func TestManagerLazyAndCache(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/big" {
			t.Errorf("list of an unused level downloaded")
		}
		if r.Header.Get("If-Modified-Since") != "" {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		io.WriteString(w, "||"+strings.TrimPrefix(r.URL.Path, "/")+".example^\n")
	}))
	defer srv.Close()
	cfg := config.DNSFilter{Default: "normal", Normal: []string{"ads"}, Paranoid: []string{"ads", "big"}, Source: srv.URL}
	dir := t.TempDir()
	var cur atomic.Pointer[Filter]
	newM := func() *Manager {
		return &Manager{Dir: dir, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
			Client: srv.Client, OnChange: func(f *Filter) { cur.Store(f) }}
	}
	m := newM()
	m.Configure(cfg, []string{"normal"})
	waitLoaded(t, m)
	m.refresh(context.Background())
	if cur.Load().Check("normal", "ads.example") != "ads" {
		t.Fatal("list not active after download")
	}
	if hits.Load() != 1 {
		t.Fatalf("%d downloads", hits.Load())
	}

	// restart: served from the cache, no download
	m2 := newM()
	m2.Configure(cfg, []string{"normal"})
	waitLoaded(t, m2)
	m2.refresh(context.Background())
	if hits.Load() != 1 || cur.Load().Check("normal", "ads.example") != "ads" {
		t.Fatalf("cache not used: %d downloads", hits.Load())
	}

	// a day later: asks with If-Modified-Since, keeps the list on 304
	m2.now = func() time.Time { return time.Now().Add(25 * time.Hour) }
	m2.refresh(context.Background())
	if hits.Load() != 2 || cur.Load().Check("normal", "ads.example") != "ads" {
		t.Fatalf("not-modified handling: %d downloads", hits.Load())
	}
	if st := m2.Status(); len(st) != 1 || st[0].Entries != 1 || st[0].Error != "" {
		t.Fatalf("status %+v", st)
	}

	// level no longer used: list dropped
	m2.Configure(cfg, nil)
	if cur.Load().Check("normal", "ads.example") != "" || len(m2.Status()) != 0 {
		t.Fatal("unused list still active")
	}
}

func waitLoaded(t *testing.T, m *Manager) {
	t.Helper()
	for i := 0; i < 200; i++ {
		m.mu.Lock()
		busy := false
		for _, e := range m.entries {
			busy = busy || e.loading
		}
		m.mu.Unlock()
		if !busy {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("cache load did not finish")
}
