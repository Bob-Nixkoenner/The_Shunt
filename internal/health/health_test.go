package health

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestStates(t *testing.T) {
	t0 := time.Unix(1_800_000_000, 0)
	var m Monitor
	if s := m.Report(t0).State; s != Unknown {
		t.Fatalf("fresh monitor: %s", s)
	}
	// fresh handshake, traffic both ways
	m.Observe(t0, 100, 100, t0)
	m.Probed(40*time.Millisecond, nil)
	if r := m.Report(t0.Add(10 * time.Second)); r.State != OK || r.LatencyMs != 40 || r.HandshakeAge != 10 {
		t.Fatalf("working tunnel: %+v", r)
	}
	// nobody uses it for 10 minutes: idle, not broken
	m.Observe(t0, 100, 100, t0.Add(10*time.Minute))
	if s := m.Report(t0.Add(10 * time.Minute)).State; s != Idle {
		t.Fatalf("idle tunnel: %s", s)
	}
	if m.ShouldReconnect(t0.Add(10 * time.Minute)) {
		t.Fatal("reconnect of an idle tunnel")
	}
}

func TestSendingWithoutAnswer(t *testing.T) {
	t0 := time.Unix(1_800_000_000, 0)
	var m Monitor
	m.Observe(t0, 100, 100, t0)
	// we keep sending, nothing comes back, handshake ages
	for i := 1; i <= 4; i++ {
		now := t0.Add(time.Duration(i) * time.Minute)
		m.Observe(t0, 100, int64(100+i*50), now)
	}
	if s := m.Report(t0.Add(4 * time.Minute)).State; s != Stale {
		t.Fatalf("after 4 deaf minutes: %s", s)
	}
	now := t0.Add(6 * time.Minute)
	m.Observe(t0, 100, 500, now)
	if s := m.Report(now).State; s != Down {
		t.Fatalf("after 6 deaf minutes: %s", s)
	}
	if !m.ShouldReconnect(now) {
		t.Fatal("down tunnel not reconnected")
	}
	if m.ShouldReconnect(now.Add(10 * time.Second)) {
		t.Fatal("reconnect again within a minute")
	}
}

func TestProbeFailures(t *testing.T) {
	t0 := time.Unix(1_800_000_000, 0)
	var m Monitor
	m.Observe(t0, 1, 1, t0)
	fail := errors.New("timeout")
	m.Probed(0, fail)
	m.Probed(0, fail)
	if s := m.Report(t0).State; s != Stale {
		t.Fatalf("2 failed probes: %s", s)
	}
	m.Probed(0, fail)
	m.Probed(0, fail)
	if r := m.Report(t0); r.State != Down || r.Loss != 1 {
		t.Fatalf("4 failed probes: %+v", r)
	}
	m.Probed(20*time.Millisecond, nil)
	if r := m.Report(t0); r.State != OK || r.Loss != 0.8 {
		t.Fatalf("after a good probe: %+v", r)
	}
}

func TestDNSProbe(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		r := new(dns.Msg)
		r.SetRcode(q, dns.RcodeRefused) // an error answer still proves the path
		w.WriteMsg(r)
	})}
	go srv.ActivateAndServe()
	defer srv.Shutdown()
	port := pc.LocalAddr().(*net.UDPAddr).Port
	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port)).String())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if rtt, err := DNSProbe(ctx, dial, netip.MustParseAddr("127.0.0.1")); err != nil || rtt <= 0 {
		t.Fatalf("probe: %v %v", rtt, err)
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel2()
	dead := func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, "127.0.0.1:9") // discard port: no answer
	}
	if _, err := DNSProbe(ctx2, dead, netip.MustParseAddr("127.0.0.1")); err == nil {
		t.Fatal("probe to a silent port succeeded")
	}
}
