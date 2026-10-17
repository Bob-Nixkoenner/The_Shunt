package stats

import (
	"path/filepath"
	"testing"
	"time"
)

func TestHistory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stats.json")
	b, _ := Open(path)
	now := time.Date(2026, 10, 17, 15, 0, 0, 0, time.Local)
	b.Observe("a", 0, 0, now.Add(-30*time.Minute)) // starting point
	b.Observe("a", 1000, 200, now.Add(-20*time.Minute))
	b.Observe("a", 1500, 300, now.Add(-2*time.Minute))
	b.Observe("b", 0, 0, now.Add(-30*time.Minute))
	b.Observe("b", 50, 5, now.Add(-2*time.Minute))
	b.ObserveDNS(4, now.Add(-10*time.Minute))
	b.ObserveDNS(4, now.Add(-9*time.Minute)) // nothing new
	b.ObserveDNS(7, now)
	b.ObserveDNS(2, now) // restart of the counter: 2 more

	h := b.History("1h", now)
	if h.Step != 300 || len(h.Points) != 12 {
		t.Fatalf("step %d points %d", h.Step, len(h.Points))
	}
	if h.RX != 1550 || h.TX != 305 {
		t.Fatalf("totals rx %d tx %d", h.RX, h.TX)
	}
	if h.DNS != 9 || h.DNSToday != 9 || h.DNSMonth != 9 {
		t.Fatalf("dns %d/%d/%d", h.DNS, h.DNSToday, h.DNSMonth)
	}
	var sum int64
	for _, v := range h.Tunnels["b"] {
		sum += v
	}
	if sum != 55 || len(h.Tunnels["b"]) != 12 {
		t.Fatalf("tunnel b: %v", h.Tunnels["b"])
	}

	// yesterday does not count as today, but as this month
	c, _ := Open("")
	c.ObserveDNS(5, now.Add(-30*time.Hour))
	c.ObserveDNS(8, now)
	if h := c.History("24h", now); h.DNSToday != 3 || h.DNSMonth != 8 {
		t.Fatalf("today %d month %d", h.DNSToday, h.DNSMonth)
	}

	// survives a restart
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	b2, _ := Open(path)
	if h := b2.History("7d", now); h.RX != 1550 || h.DNSMonth != 9 {
		t.Fatalf("after reopen: rx %d month %d", h.RX, h.DNSMonth)
	}
	if h := b2.History("nonsense", now); h.Range != "24h" {
		t.Fatalf("range %q", h.Range)
	}
}

func TestSeriesIsBounded(t *testing.T) {
	b, _ := Open("")
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	b.Observe("a", 0, 0, start)
	for i := 1; i <= keepSlots+500; i++ {
		b.Observe("a", int64(i), 0, start.Add(time.Duration(i)*slotSecs*time.Second))
	}
	if len(b.f.Series) != keepSlots {
		t.Fatalf("%d slots", len(b.f.Series))
	}
}
