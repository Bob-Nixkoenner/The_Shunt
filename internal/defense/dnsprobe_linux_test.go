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

// The public resolver is asked only while the default route is a tunnel,
// and the daemon is asked again for every attempt.
func TestDNSCheckPublicNeedsTunnel(t *testing.T) {
	s := &Sensors{Mark: 0x10}
	if c := s.dnsCheck(); c.Dial == nil || c.PublicDial != nil {
		t.Fatal("no TunnelMark: local dialer set, public resolver not asked")
	}
	up := false
	var asked int
	s.TunnelMark = func() (uint32, bool) { asked++; return 0x20, up }
	if c := s.dnsCheck(); c.PublicDial != nil {
		t.Fatal("default route is no tunnel: public resolver must not be asked")
	}
	up = true
	if c := s.dnsCheck(); c.PublicDial == nil {
		t.Fatal("default route is a tunnel: public resolver goes through it")
	}
	up = false
	if c := s.dnsCheck(); c.PublicDial != nil || asked != 3 {
		t.Fatalf("tunnel gone: public resolver still asked (TunnelMark calls %d)", asked)
	}
}
