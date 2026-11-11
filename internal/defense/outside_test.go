package defense

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func fakeServer(t *testing.T, token string, answer func() any) (*httptest.Server, *[]string) {
	var hits []string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, r.Method+" "+r.URL.Path+" body="+readAll(r))
		if token != "" && r.Header.Get("X-Shunt-Token") != token {
			http.Error(w, "no", http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(answer())
	}))
	t.Cleanup(s.Close)
	return s, &hits
}

func readAll(r *http.Request) string {
	b := make([]byte, 64)
	n, _ := r.Body.Read(b)
	return string(b[:n])
}

func ownIs(addrs ...string) func(netip.Addr) bool {
	return func(a netip.Addr) bool {
		for _, x := range addrs {
			if netip.MustParseAddr(x) == a {
				return true
			}
		}
		return false
	}
}

func TestOutsideScanOK(t *testing.T) {
	srv, hits := fakeServer(t, "s3", func() any {
		return map[string]any{"addr": "192.0.2.50", "open": []int{80, 22, 22}, "scanned": 40}
	})
	cfg := OutsideScanConfig{Enabled: true, Host: srv.URL, Token: "s3"}
	res, err := OutsideScan(context.Background(), cfg, Exposure{V4: true}, func(string) *http.Client { return srv.Client() }, ownIs("192.0.2.50"))
	if err != nil || len(res.Checks) != 1 {
		t.Fatalf("%v %+v", err, res)
	}
	c := res.Checks[0]
	if c.Family != "v4" || c.Error != "" || len(c.Open) != 2 || c.Open[0] != 22 || c.Open[1] != 80 || c.Scanned != 40 {
		t.Fatalf("%+v", c)
	}
	if len(*hits) != 1 || !strings.HasPrefix((*hits)[0], "POST / body={}") {
		t.Fatalf("the client sends no target or port list: %v", *hits)
	}
}

func TestOutsideScanRefusesForeignAddress(t *testing.T) {
	srv, _ := fakeServer(t, "", func() any { return map[string]any{"addr": "198.51.100.7", "open": []int{22}} })
	cfg := OutsideScanConfig{Enabled: true, Host: srv.URL}
	res, _ := OutsideScan(context.Background(), cfg, Exposure{V4: true}, func(string) *http.Client { return srv.Client() }, ownIs("192.0.2.50"))
	if c := res.Checks[0]; c.Error == "" || len(c.Open) != 0 {
		t.Fatalf("a foreign address must be refused: %+v", c)
	}
}

func TestOutsideScanBadAnswers(t *testing.T) {
	for name, ans := range map[string]any{
		"family":   map[string]any{"addr": "2001:db8::5", "open": []int{22}},
		"port":     map[string]any{"addr": "192.0.2.50", "open": []int{70000}},
		"too many": map[string]any{"addr": "192.0.2.50", "open": make([]int, MaxOutsidePorts+1)},
		"error":    map[string]any{"error": "rate limit"},
		"noaddr":   map[string]any{"open": []int{1}},
	} {
		srv, _ := fakeServer(t, "", func() any { return ans })
		res, _ := OutsideScan(context.Background(), OutsideScanConfig{Enabled: true, Host: srv.URL}, Exposure{V4: true},
			func(string) *http.Client { return srv.Client() }, ownIs("192.0.2.50"))
		if res.Checks[0].Error == "" {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestOutsideScanGuards(t *testing.T) {
	cl := func(string) *http.Client { return http.DefaultClient }
	if _, err := OutsideScan(context.Background(), OutsideScanConfig{Host: "https://x.example"}, Exposure{V4: true}, cl, nil); err == nil {
		t.Error("off by default")
	}
	if _, err := OutsideScan(context.Background(), OutsideScanConfig{Enabled: true, Host: "https://x.example"}, Exposure{}, cl, nil); err == nil {
		t.Error("no public address: nothing to check")
	}
	srv, hits := fakeServer(t, "", func() any { return map[string]any{} })
	_, _ = OutsideScan(context.Background(), OutsideScanConfig{Enabled: true, Host: srv.URL}, Exposure{}, cl, nil)
	if len(*hits) != 0 {
		t.Error("no request without a public address")
	}
	// wrong token: server says 403
	srv2, _ := fakeServer(t, "right", func() any { return map[string]any{"addr": "192.0.2.50"} })
	res, _ := OutsideScan(context.Background(), OutsideScanConfig{Enabled: true, Host: srv2.URL, Token: "wrong"}, Exposure{V4: true},
		func(string) *http.Client { return srv2.Client() }, ownIs("192.0.2.50"))
	if !strings.Contains(res.Checks[0].Error, "403") {
		t.Errorf("%+v", res.Checks[0])
	}
}

func TestValidateOutsideScan(t *testing.T) {
	for host, ok := range map[string]bool{"": true, "https://scan.example/x": true, "http://192.0.2.9:8080/": true,
		"ssh://u@h": false, "https://u:p@h/": false, "scan.example": false, "https:///x": false} {
		err := ValidateOutsideScan(OutsideScanConfig{Host: host})
		if (err == nil) != ok {
			t.Errorf("%q: %v", host, err)
		}
	}
	if ValidateOutsideScan(OutsideScanConfig{Enabled: true}) == nil {
		t.Error("enabled needs a host")
	}
}

func TestSetOutsideEvent(t *testing.T) {
	m, _, _ := expoManager(t)
	m.SetOutside(OutsideResult{Checks: []OutsideCheck{{Family: "v4", Open: []int{22, 80}}, {Family: "v6", Open: []int{}}}})
	st := m.Status()
	if st.Outside == nil || st.Outside.OpenCount() != 2 {
		t.Fatalf("%+v", st.Outside)
	}
	var ev Event
	for _, e := range m.Events(0).Events {
		if e.Kind == KindOutside {
			ev = e
		}
	}
	if ev.Severity != SevHigh || ev.Detail != "open v4=22,80 v6=none" {
		t.Fatalf("%+v", ev)
	}
	m.SetOutside(OutsideResult{Checks: []OutsideCheck{{Family: "v4", Open: []int{}}}})
	last := m.Events(0).Events
	if e := last[len(last)-1]; e.Severity != SevInfo {
		t.Fatalf("nothing open is info: %+v", e)
	}
}
