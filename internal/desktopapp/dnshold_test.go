package desktopapp

import (
	"testing"
	"time"
)

func TestDNSHold(t *testing.T) {
	var h DNSHold
	t0 := time.Unix(1000, 0)
	f := map[string]string{"tunnel:a": "timeout"}
	if got := h.Filter(f, t0, time.Minute); len(got) != 0 {
		t.Fatal("reported at once")
	}
	if got := h.Filter(f, t0.Add(59*time.Second), time.Minute); len(got) != 0 {
		t.Fatal("reported too early")
	}
	if got := h.Filter(f, t0.Add(60*time.Second), time.Minute); got["tunnel:a"] != "timeout" {
		t.Fatal("not reported after the hold time")
	}
	// it works for a moment: the clock starts again
	h.Filter(nil, t0.Add(70*time.Second), time.Minute)
	if got := h.Filter(f, t0.Add(80*time.Second), time.Minute); len(got) != 0 {
		t.Fatal("old failure time kept after a recovery")
	}
}
