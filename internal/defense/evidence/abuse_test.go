package evidence

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const rdapSample = `{"objectClassName":"ip network","handle":"NET-192-0-2-0-1","name":"EXAMPLE-NET","country":"ZZ",
"startAddress":"192.0.2.0","endAddress":"192.0.2.255","cidr0_cidrs":[{"v4prefix":"192.0.2.0","length":24}],
"entities":[{"roles":["registrant"],"vcardArray":["vcard",[["fn",{},"text","Example Org"]]],
 "entities":[{"roles":["abuse"],"vcardArray":["vcard",[["fn",{},"text","Abuse Desk"],["email",{},"text","abuse@example.net"]]]}]}]}`

func TestParseRDAP(t *testing.T) {
	in, err := ParseRDAP([]byte(rdapSample))
	if err != nil {
		t.Fatal(err)
	}
	if in.AbuseEmail != "abuse@example.net" || in.Country != "ZZ" || in.Network != "192.0.2.0/24" || !strings.Contains(in.Operator, "Example Org") {
		t.Fatalf("%+v", in)
	}
	for _, bad := range []string{`{}`, `not json`, `{"objectClassName":"domain","name":"x"}`} {
		if _, err := ParseRDAP([]byte(bad)); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	// an e-mail with markup is not taken over
	in, _ = ParseRDAP([]byte(`{"name":"N","entities":[{"roles":["abuse"],"vcardArray":["vcard",[["email",{},"text","a@b.c <x>"]]]}]}`))
	if in.AbuseEmail != "" {
		t.Fatal("odd e-mail accepted")
	}
}

func TestAbuseLookupBootstrapCacheAndErrors(t *testing.T) {
	var hits, boots atomic.Int32
	var rdapURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/ipv4.json", func(w http.ResponseWriter, r *http.Request) {
		boots.Add(1)
		if r.Header.Get("User-Agent") != "rdap-client" {
			t.Errorf("user agent %q", r.Header.Get("User-Agent"))
		}
		w.Write([]byte(`{"services":[[["192.0.0.0/8"],["` + rdapURL + `/wrong/"]],[["192.0.2.0/24"],["` + rdapURL + `/rdap/"]]]}`))
	})
	mux.HandleFunc("/rdap/ip/192.0.2.9", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte(rdapSample))
	})
	mux.HandleFunc("/rdap/ip/192.0.2.10", func(w http.ResponseWriter, r *http.Request) { http.Error(w, "x", 500) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	rdapURL = srv.URL
	now := time.Date(2026, 11, 11, 9, 0, 0, 0, time.UTC)
	a := &Abuser{Bootstrap: srv.URL, AllowHTTP: true, CacheFile: filepath.Join(t.TempDir(), "evidence", AbuseCacheName), Now: func() time.Time { return now }}
	in, err := a.Lookup(context.Background(), "192.0.2.9")
	if err != nil || in.AbuseEmail != "abuse@example.net" || in.Cached || in.Registry == "" {
		t.Fatalf("%+v %v", in, err)
	}
	in, err = a.Lookup(context.Background(), "192.0.2.9")
	if err != nil || !in.Cached || hits.Load() != 1 {
		t.Fatalf("second lookup must come from the cache: %+v %v hits=%d", in, err, hits.Load())
	}
	if fi, _ := os.Stat(a.CacheFile); fi.Mode().Perm() != 0o600 {
		t.Fatalf("cache mode %v", fi.Mode())
	}
	now = now.Add(8 * 24 * time.Hour) // cache expired
	if _, err := a.Lookup(context.Background(), "192.0.2.9"); err != nil || hits.Load() != 2 {
		t.Fatalf("expired cache not refreshed: hits=%d err=%v", hits.Load(), err)
	}
	if _, err := a.Lookup(context.Background(), "192.0.2.10"); err == nil {
		t.Fatal("registry error not reported")
	}
	for _, ip := range []string{"10.1.2.3", "127.0.0.1", "169.254.1.1", "::1", "fe80::1", "nonsense", ""} {
		if _, err := a.Lookup(context.Background(), ip); err == nil {
			t.Fatalf("%q accepted", ip)
		}
	}
	// https only unless tests allow it
	b := &Abuser{Bootstrap: srv.URL}
	if _, err := b.Lookup(context.Background(), "192.0.2.9"); err == nil {
		t.Fatal("plain http used")
	}
}

func TestAbuseTimeoutAndHugeAnswer(t *testing.T) {
	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(strings.Repeat("a", abuseMaxBody+10)))
	}))
	defer big.Close()
	a := &Abuser{Bootstrap: big.URL, AllowHTTP: true}
	if _, err := a.Lookup(context.Background(), "198.51.100.5"); err == nil {
		t.Fatal("oversized answer accepted")
	}
}
