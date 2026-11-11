package defense

import (
	"net/netip"
	"testing"
	"time"
)

// One source flooding SYNs to many ports within the window: memory per
// source stays capped and the scan is still found.
func TestDetectorFloodOneSource(t *testing.T) {
	d := NewDetector(DetectConfig{}, nil)
	found := 0
	d.OnFound = func(Finding) { found++ }
	src := netip.MustParseAddr("192.0.2.7")
	start := time.Now()
	for i := 0; i < 100000; i++ {
		d.ObserveState(src, 1+i%60000, "tcp", StateS0)
	}
	if el := time.Since(start); el > 10*time.Second {
		t.Fatalf("flood took %v", el)
	}
	st := d.src[src]
	if len(st.fails) > maxTrackedFails || len(st.ports) > maxTrackedPorts {
		t.Fatalf("fails=%d ports=%d", len(st.fails), len(st.ports))
	}
	if found == 0 {
		t.Fatal("scan not found")
	}
}
