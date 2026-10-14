package daemon

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/dnsproxy"
	"github.com/Bob-Nixkoenner/the_shunt/internal/tunnel"
	"github.com/miekg/dns"
)

type healthDev struct{ tx atomic.Int64 }

func (*healthDev) DriverName() string                    { return "fake" }
func (*healthDev) Down()                                 {}
func (*healthDev) Alive() bool                           { return true }
func (*healthDev) Reresolve(time.Time) ([]string, error) { return nil, nil }
func (*healthDev) Err() string                           { return "" }
func (h *healthDev) Status() ([]tunnel.PeerStatus, error) {
	return []tunnel.PeerStatus{{LastHandshake: time.Now(), RxBytes: h.tx.Load(), TxBytes: h.tx.Add(100)}}, nil
}

type healthUp struct{ fail atomic.Bool }

func (u *healthUp) Exchange(context.Context, *dns.Msg) (*dns.Msg, error) {
	time.Sleep(2 * time.Millisecond)
	if u.fail.Load() {
		return nil, errors.New("timeout")
	}
	return new(dns.Msg), nil
}
func (*healthUp) String() string { return "fake" }

func TestCheckHealth(t *testing.T) {
	up := &healthUp{}
	d := &Daemon{Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		tunnels: map[string]tunnel.Device{"t": &healthDev{}},
		dnsUps:  dnsproxy.RouteUpstreams{"tunnel:t": {up}}}
	d.checkHealth()
	d.checkHealth()
	r := d.healthReport("t")
	if r == nil || r.State != "ok" || r.LatencyMs < 1 {
		t.Fatalf("working tunnel: %+v", r)
	}
	up.fail.Store(true)
	d.checkHealth()
	d.checkHealth()
	if r := d.healthReport("t"); r.State != "stale" || r.Loss == 0 {
		t.Fatalf("failing probes: %+v", r)
	}
	delete(d.tunnels, "t")
	d.checkHealth()
	if d.healthReport("t") != nil {
		t.Fatal("removed tunnel still has a monitor")
	}
}
