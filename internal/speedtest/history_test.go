package speedtest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func rep(seed uint64) *Report {
	return &Report{Provider: Cloudflare, Rounds: 3, Seed: seed, Started: time.Unix(1700000000+int64(seed), 0),
		Routes: []RouteResult{{Route: "direct", State: "ok", DownMbit: 90, UpMbit: 20, LatencyMs: 10, IP: "203.0.113.5", Loc: "DE"}}}
}

func TestHistoryRotatesAndKeepsNoAddresses(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "h.json")
	for i := uint64(1); i <= 5; i++ {
		if err := AddHistory(p, rep(i), "home"); err != nil {
			t.Fatal(err)
		}
	}
	h := LoadHistory(p)
	if len(h) != 3 || h[0].Seed != 5 || h[2].Seed != 3 || h[0].Network != "home" {
		t.Fatalf("%+v", h)
	}
	b, _ := os.ReadFile(p)
	if strings.Contains(string(b), "203.0.113") || strings.Contains(string(b), "DE\"") {
		t.Fatalf("address stored: %s", b)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	if m, _ := filepath.Glob(filepath.Join(filepath.Dir(p), ".speedtest-history-*")); len(m) != 0 {
		t.Fatalf("temp left: %v", m)
	}
}

func TestHistoryBrokenFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "h.json")
	_ = os.WriteFile(p, []byte("{not json"), 0o600)
	if h := LoadHistory(p); len(h) != 0 {
		t.Fatalf("%v", h)
	}
	if err := AddHistory(p, rep(1), ""); err != nil {
		t.Fatal(err)
	}
	if h := LoadHistory(p); len(h) != 1 {
		t.Fatalf("%v", h)
	}
	if LoadHistory(filepath.Join(t.TempDir(), "none")) != nil {
		t.Fatal("missing file")
	}
}
