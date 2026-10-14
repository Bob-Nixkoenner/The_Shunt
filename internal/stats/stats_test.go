package stats

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCounting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stats.json")
	b, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	sep := time.Date(2026, 9, 30, 23, 0, 0, 0, time.UTC)
	oct := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

	b.Observe("home", 1000, 500, sep) // starting point only
	b.Observe("home", 1600, 700, sep.Add(time.Minute))
	b.Observe("home", 100, 50, oct) // tunnel re-created: counters restarted
	b.Observe("home", 400, 150, oct.Add(time.Minute))
	b.Observe("work", 0, 0, oct)
	b.Observe("work", 50, 10, oct.Add(time.Minute))

	s := b.Summaries(oct)
	if h := s["home"]; h.LastMonth != (Bytes{600, 200}) || h.Month != (Bytes{400, 150}) || h.Total != (Bytes{1000, 350}) {
		t.Errorf("home: %+v", h)
	}
	if tot := s["total"]; tot.Month != (Bytes{450, 160}) || tot.Total != (Bytes{1050, 360}) || tot.Since != sep.Add(time.Minute).Unix() {
		t.Errorf("total: %+v", tot)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}

	// reopened: totals are back, the first counter value is a new start
	b2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	b2.Observe("home", 400, 150, oct.Add(2*time.Minute))
	if h := b2.Summaries(oct)["home"]; h.Total != (Bytes{1000, 350}) {
		t.Errorf("after reopen: %+v", h)
	}
	if ms := b2.Months("home"); len(ms) != 2 || ms[0].Month != "2026-09" || ms[1].Month != "2026-10" {
		t.Errorf("months: %+v", ms)
	}
	b2.Reset()
	if tot := b2.Summaries(oct)["total"]; tot.Total != (Bytes{}) {
		t.Errorf("after reset: %+v", tot)
	}
}

func TestBrokenFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stats.json")
	os.WriteFile(path, []byte("{nope"), 0o600)
	b, err := Open(path)
	if err != nil {
		t.Fatalf("a broken file must not stop the VPN: %v", err)
	}
	if _, err := os.Stat(path + ".broken"); err != nil {
		t.Error("broken file not kept")
	}
	now := time.Now()
	b.Observe("x", 1, 1, now)
	b.Observe("x", 2, 2, now)
	if s := b.Summaries(now)["x"]; s.Total != (Bytes{1, 1}) {
		t.Errorf("%+v", s)
	}
}

func TestSaveThrottle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stats.json")
	b, _ := Open(path)
	now := time.Now()
	b.Observe("x", 0, 0, now)
	b.Observe("x", 10, 10, now) // first growth: saved (never saved before)
	if raw, _ := os.ReadFile(path); !strings.Contains(string(raw), `"rx":10`) {
		t.Fatalf("first save: %s", raw)
	}
	b.Observe("x", 20, 20, now.Add(time.Minute)) // within SaveEvery: not yet on disk
	if raw, _ := os.ReadFile(path); !strings.Contains(string(raw), `"rx":10`) {
		t.Errorf("saved again within SaveEvery: %s", raw)
	}
	b.Close()
	if raw, _ := os.ReadFile(path); !strings.Contains(string(raw), `"rx":20`) {
		t.Errorf("Close did not save: %s", raw)
	}
}
