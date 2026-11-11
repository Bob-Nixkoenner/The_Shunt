package defense

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

// With the DNS probe off, the active comparison must not run at all.
func TestDNSRoundNeedsProbe(t *testing.T) {
	m := NewManager(nil)
	defer m.Close()
	cfg := DefaultConfig()
	cfg.Enabled = true
	m.Configure(cfg)
	var calls atomic.Int32
	s := &Sensors{M: m, DNS: DNSCheck{Reference: func(context.Context, string) ([]netip.Addr, error) {
		calls.Add(1)
		return nil, context.Canceled
	}}}
	var once dnsOnce
	var noted bool
	fast := func(context.Context, time.Duration) bool { return true }
	s.dnsRound(context.Background(), Env{DNSProbe: false}, &once, &noted, fast)
	if calls.Load() != 0 {
		t.Fatal("probe ran while off")
	}
	s.dnsRound(context.Background(), Env{DNSProbe: true}, &once, &noted, fast)
	if calls.Load() == 0 {
		t.Fatal("probe did not run while on")
	}
}
