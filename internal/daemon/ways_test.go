package daemon

import (
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/stats"
)

type fakeWays struct {
	loads       int
	setErr      error
	readErr     error
	direct, lan stats.Bytes
	ifaces      []string
	eps         []netip.Addr
}

func (f *fakeWays) SetWays(i []string, e []netip.Addr) error {
	if f.setErr != nil {
		return f.setErr
	}
	f.loads++
	f.ifaces, f.eps = i, e
	return nil
}

func (f *fakeWays) ReadWays() (stats.Bytes, stats.Bytes, error) {
	return f.direct, f.lan, f.readErr
}

func (f *fakeWays) WaysOff() error { return nil }

func TestWaysIfaces(t *testing.T) {
	_, p := guardPlan(t)
	if got := waysIfaces(p); !slices.Equal(got, []string{"sh-home", "sh-vps"}) {
		t.Fatalf("got %v", got)
	}
	p.RouteByName("tunnel:home").Tor = true
	if got := waysIfaces(p); !slices.Equal(got, []string{"sh-vps"}) {
		t.Fatalf("tor route counted: %v", got)
	}
	if waysIfaces(nil) != nil {
		t.Fatal("nil plan")
	}
}

func TestEndpointAddrs(t *testing.T) {
	got := endpointAddrs([]string{"203.0.113.9:51820", "[2001:db8::1]:443", "vpn.example.org:51820", "198.51.100.2", "203.0.113.9:1194", "[::ffff:192.0.2.1]:1"})
	want := []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.2"), netip.MustParseAddr("203.0.113.9"), netip.MustParseAddr("2001:db8::1")}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestCountWays(t *testing.T) {
	d := &Daemon{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	book, _ := stats.Open("")
	f := &fakeWays{}
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	ifs := []string{"sh-vps"}
	eps := []netip.Addr{netip.MustParseAddr("203.0.113.9")}
	tick := func() {
		now = now.Add(30 * time.Second)
		d.countWays(f, book, ifs, eps, now)
	}
	total := func(name string) stats.Bytes { return book.Summaries(now)[name].Total }

	f.direct, f.lan = stats.Bytes{RX: 1000, TX: 100}, stats.Bytes{RX: 50, TX: 5}
	tick() // first reading: the starting point
	f.direct, f.lan = stats.Bytes{RX: 3000, TX: 300}, stats.Bytes{RX: 70, TX: 9}
	tick()
	if f.loads != 1 {
		t.Fatalf("loaded %d times, want 1 (nothing changed)", f.loads)
	}
	if got := total(stats.WayDirect); got != (stats.Bytes{RX: 2000, TX: 200}) {
		t.Fatalf("direct = %+v", got)
	}
	if got := total(stats.WayLAN); got != (stats.Bytes{RX: 20, TX: 4}) {
		t.Fatalf("lan = %+v", got)
	}
	if got := book.Summaries(now)["total"].Total; got != (stats.Bytes{}) {
		t.Fatalf("direct/lan counted into the tunnel total: %+v", got)
	}

	// a new endpoint: rules loaded again, counters go on
	eps = append(eps, netip.MustParseAddr("198.51.100.2"))
	tick()
	if f.loads != 2 || len(f.eps) != 2 {
		t.Fatalf("loads %d, eps %v", f.loads, f.eps)
	}

	// the table vanished (counters back at zero): reloaded, a restart is no loss
	f.readErr = errors.New("no such table")
	tick()
	if d.waysKey != "" {
		t.Fatal("key kept after a failed read")
	}
	f.readErr = nil
	f.direct, f.lan = stats.Bytes{RX: 10, TX: 1}, stats.Bytes{}
	tick()
	if f.loads != 3 {
		t.Fatalf("not reloaded after the table vanished: %d", f.loads)
	}
	if got := total(stats.WayDirect); got != (stats.Bytes{RX: 2010, TX: 201}) {
		t.Fatalf("after restart direct = %+v", got)
	}

	// loading fails: no numbers, no panic, tried again next time
	f.setErr = errors.New("nft: permission denied")
	eps = eps[:1]
	tick()
	tick()
	if !d.waysWarned || d.waysKey != "" {
		t.Fatalf("warned %v key %q", d.waysWarned, d.waysKey)
	}
	f.setErr = nil
	tick()
	if d.waysWarned || f.loads != 4 {
		t.Fatalf("not loaded again: warned %v loads %d", d.waysWarned, f.loads)
	}
}
