package dnsproxy

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/miekg/dns"
)

// A UDP server that drops the first packet: the second try answers, long
// before the full timeout.
func TestUDPRetryAfterLostPacket(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer pc.Close()
	var n atomic.Int32
	go func() {
		buf := make([]byte, 512)
		for {
			k, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n.Add(1) == 1 {
				continue // lost
			}
			q := new(dns.Msg)
			if q.Unpack(buf[:k]) != nil {
				continue
			}
			r := new(dns.Msg)
			r.SetReply(q)
			w, _ := r.Pack()
			pc.WriteTo(w, from)
		}
	}()
	// no packet mark here (SO_MARK needs root): the client without NewUpstream's dialer
	u := &classicUpstream{
		spec:   config.UpstreamSpec{Proto: "udp", Addr: netip.MustParseAddrPort(pc.LocalAddr().String())},
		client: &dns.Client{Net: "udp", Timeout: upstreamTimeout},
	}
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	ctx, cancel := context.WithTimeout(context.Background(), 2*upstreamTimeout)
	defer cancel()
	t0 := time.Now()
	if _, err := u.Exchange(ctx, m); err != nil {
		t.Fatalf("no answer after a lost packet: %v", err)
	}
	if d := time.Since(t0); d > 3*time.Second {
		t.Errorf("took %v, the retry should come after about %v", d, udpRetryAfter)
	}
	if n.Load() != 2 {
		t.Errorf("server saw %d packets, want 2", n.Load())
	}
}
