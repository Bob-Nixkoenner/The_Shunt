package daemon

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/api"
	"github.com/Bob-Nixkoenner/the_shunt/internal/check"
)

func ignoreCall(t *testing.T, mux http.Handler, method, path string, body any, peer bool) *httptest.ResponseRecorder {
	t.Helper()
	var b []byte
	if body != nil {
		b, _ = json.Marshal(body)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(b))
	if peer {
		req = req.WithContext(withTestPeer(req.Context()))
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func hasFinding(fs []check.Finding, id, rule string) bool {
	for _, f := range fs {
		if f.ID == id && (rule == "" || f.Vals["rule"] == rule) {
			return true
		}
	}
	return false
}

// Bob's case: strict check, an app that goes direct on purpose. Its warning
// can be hidden per rule; the other rule's stays; the list survives a
// restart; showing it again needs no permission, hiding does.
func TestHideWarningRoutes(t *testing.T) {
	d, _ := testDaemon(t, "[daemon]\nsocket = \"/nonexistent/s.sock\"\nconfig_check = \"strict\"\n[dns]\ndisabled = true\n"+
		"[[rule]]\nname = \"banking\"\nport = [\"tcp/4443\"]\nroute = \"direct\"\n"+
		"[[rule]]\nname = \"printer\"\nport = [\"tcp/631\"]\nroute = \"direct\"\n")
	if err := d.reload("shunt"); err != nil {
		t.Fatal(err)
	}
	mux := d.routes()
	st := d.status()
	var key string
	for _, f := range st.Findings {
		if f.ID == "rule.direct" && f.Vals["rule"] == "banking" {
			key = f.Key
		}
		if f.ID == "dns.off" && f.Key != "" {
			t.Fatal("dns.off offered for hiding")
		}
	}
	if key != "rule.direct:banking" {
		t.Fatalf("no key for the direct rule: %+v", st.Findings)
	}

	if rec := ignoreCall(t, mux, "POST", "/v1/warnings/ignore", api.IgnoreRequest{Key: key, For: "week"}, false); rec.Code != http.StatusForbidden {
		t.Fatalf("hide without permission: %d", rec.Code)
	}
	if rec := ignoreCall(t, mux, "POST", "/v1/warnings/ignore", api.IgnoreRequest{Key: "dns.off", For: "day"}, true); rec.Code != http.StatusNotFound {
		t.Fatalf("hide dns.off: %d", rec.Code)
	}
	if rec := ignoreCall(t, mux, "POST", "/v1/warnings/ignore", api.IgnoreRequest{Key: key, For: "month"}, true); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad duration: %d", rec.Code)
	}
	if rec := ignoreCall(t, mux, "POST", "/v1/warnings/ignore", api.IgnoreRequest{Key: key, For: "week"}, true); rec.Code != http.StatusOK {
		t.Fatalf("hide: %d %s", rec.Code, rec.Body)
	}

	st = d.status()
	if hasFinding(st.Findings, "rule.direct", "banking") || !hasFinding(st.Findings, "rule.direct", "printer") || !hasFinding(st.Findings, "dns.off", "") {
		t.Fatalf("after hiding: %+v", st.Findings)
	}
	if st.Hidden != 1 || len(st.Ignored) != 1 || !st.Ignored[0].Hiding || st.Ignored[0].Until.IsZero() {
		t.Fatalf("hidden %d ignored %+v", st.Hidden, st.Ignored)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(d.ConfigPath), "ignored.json")); err != nil {
		t.Fatal(err)
	}

	// a restart reads the list again
	d2, _ := testDaemon(t, "")
	d2.ConfigPath = d.ConfigPath
	if err := d2.reload("shunt"); err != nil {
		t.Fatal(err)
	}
	if st := d2.status(); hasFinding(st.Findings, "rule.direct", "banking") || st.Hidden != 1 {
		t.Fatalf("after restart: %+v", st.Findings)
	}

	var ls []check.Ignored
	if rec := ignoreCall(t, mux, "GET", "/v1/warnings/ignored", nil, false); rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &ls) != nil || len(ls) != 1 {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}
	if rec := ignoreCall(t, mux, "DELETE", "/v1/warnings/ignore?key="+key, nil, false); rec.Code != http.StatusNoContent {
		t.Fatalf("show again: %d", rec.Code)
	}
	if rec := ignoreCall(t, mux, "DELETE", "/v1/warnings/ignore?key="+key, nil, false); rec.Code != http.StatusNotFound {
		t.Fatalf("show again twice: %d", rec.Code)
	}
	if st := d.status(); !hasFinding(st.Findings, "rule.direct", "banking") || st.Hidden != 0 || len(st.Ignored) != 0 {
		t.Fatalf("shown again: %+v", st)
	}
}
