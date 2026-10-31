package probe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestJudge(t *testing.T) {
	rs := []RouteResult{
		{Route: "direct", Result: Result{IP: "1.1.1.1", Resolver: "9.9.9.9"}},
		{Route: "block"},
		{Route: "tunnel:good", Result: Result{IP: "2.2.2.2", Resolver: "8.8.8.8"}},
		{Route: "tunnel:leaky", Result: Result{IP: "1.1.1.1", Resolver: "8.8.8.8"}},
		{Route: "tunnel:dnsleak", Result: Result{IP: "2.2.2.2", Resolver: "9.9.9.9"}},
		{Route: "tunnel:down", Result: Result{IPErr: "x", DNSErr: "y"}},
		{Route: "tunnel:err", Verdict: "error"},
		{Route: "link:ethernet", Result: Result{IP: "1.1.1.1", Resolver: "9.9.9.9"}},
		{Route: "link:wifi"},
	}
	judge(rs)
	want := []string{"ok", "blocked", "ok", "leak", "warn", "blocked", "error", "ok", "blocked"}
	for i, w := range want {
		if rs[i].Verdict != w {
			t.Errorf("%s: got %s want %s", rs[i].Route, rs[i].Verdict, w)
		}
	}
}

func TestJudgeTor(t *testing.T) {
	d := Result{IP: "1.1.1.1", Resolver: "9.9.9.9"}
	rs := []RouteResult{
		{Route: "direct", Result: d},
		{Route: "tunnel:t1", Result: Result{Tor: true, IP: "2.2.2.2", IsTor: true}},
		{Route: "tunnel:t2", Result: Result{Tor: true, IP: "2.2.2.2", TorErr: "timeout"}},
		{Route: "tunnel:t3", Result: Result{Tor: true, IP: "2.2.2.2"}},
		{Route: "tunnel:t4", Result: Result{Tor: true, IP: "1.1.1.1", IsTor: true}},
		{Route: "tunnel:t5", Result: Result{Tor: true, IPErr: "x"}},
		// the IP service failed but check.torproject.org came through Tor: Tor works
		{Route: "tunnel:t6", Result: Result{Tor: true, IPErr: "x", IsTor: true}},
	}
	judge(rs)
	if rs[5].Detail != "x" {
		t.Errorf("blocked Tor: detail %q, want the IP error", rs[5].Detail)
	}
	want := []string{"ok", "ok", "ok", "warn", "leak", "blocked", "ok"}
	for i, w := range want {
		if rs[i].Verdict != w {
			t.Errorf("%s: got %s want %s", rs[i].Route, rs[i].Verdict, w)
		}
	}
}

func TestRunTor(t *testing.T) {
	ip := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("2.2.2.2")) }))
	defer ip.Close()
	tor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"IsTor":true,"IP":"2.2.2.2"}`)) }))
	defer tor.Close()
	oi, ot := IPURL, TorURL
	IPURL, TorURL = ip.URL, tor.URL
	defer func() { IPURL, TorURL = oi, ot }()
	r := RunTor(context.Background())
	if !r.Tor || !r.IsTor || r.IP != "2.2.2.2" || r.Resolver != "" || r.DNSErr != "" {
		t.Fatalf("%+v", r)
	}
}
