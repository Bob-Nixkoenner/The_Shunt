// Package health judges whether a WireGuard tunnel works, the same way on
// every platform: from the handshake age and byte counters, plus a small
// probe through the tunnel (a DNS query to the tunnel's DNS server, which
// also gives the latency).
//
// WireGuard re-handshakes about every 2 minutes while packets flow, so an
// old handshake alone only means "idle". A tunnel is in trouble when we
// send but get nothing back, or when probes fail.
package health

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// States.
const (
	Unknown = "unknown" // no data yet
	OK      = "ok"
	Idle    = "idle"  // no traffic, nothing wrong
	Stale   = "stale" // sending without answers, or probes failing
	Down    = "down"  // no handshake/answers for a long time: reconnect
)

const (
	staleAfter    = 3 * time.Minute // handshake older than this while sending
	downAfter     = 5 * time.Minute
	failsForStale = 2 // probes in a row
	failsForDown  = 4
	reconnectGap  = time.Minute // at most one reconnect per gap
)

// Report is what UIs show.
type Report struct {
	State        string  `json:"state"`
	LatencyMs    int64   `json:"latency_ms,omitempty"` // smoothed probe round trip
	Loss         float64 `json:"loss"`                 // share of failed probes (last 20)
	HandshakeAge int64   `json:"handshake_age"`        // seconds, -1 = never
}

// Monitor follows one tunnel. Safe for concurrent use.
type Monitor struct {
	mu        sync.Mutex
	handshake time.Time
	rx, tx    int64
	rxAt      time.Time // last time rx grew
	txAt      time.Time // last time tx grew
	observed  bool
	rtt       time.Duration // EWMA
	fails     int           // probes failed in a row
	results   []bool        // last probe results, true = ok
	lastRecon time.Time
}

// Observe feeds the tunnel's counters (from wg / IpcGet).
func (m *Monitor) Observe(handshake time.Time, rx, tx int64, now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.observed || rx > m.rx {
		m.rxAt = now
	}
	if !m.observed || tx > m.tx {
		m.txAt = now
	}
	m.handshake, m.rx, m.tx, m.observed = handshake, rx, tx, true
}

// Probed records a probe result.
func (m *Monitor) Probed(rtt time.Duration, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ok := err == nil
	m.results = append(m.results, ok)
	if len(m.results) > 20 {
		m.results = m.results[1:]
	}
	if !ok {
		m.fails++
		return
	}
	m.fails = 0
	if m.rtt == 0 {
		m.rtt = rtt
	} else {
		m.rtt = (m.rtt*7 + rtt) / 8
	}
}

func (m *Monitor) state(now time.Time) string {
	if !m.observed && len(m.results) == 0 {
		return Unknown
	}
	if m.fails >= failsForDown {
		return Down
	}
	never := m.handshake.IsZero()
	age := now.Sub(m.handshake)
	// sending without anything coming back
	sendingDeaf := m.txAt.After(m.rxAt) && now.Sub(m.rxAt) > staleAfter
	if (never || age > downAfter) && sendingDeaf {
		return Down
	}
	if m.fails >= failsForStale || sendingDeaf {
		return Stale
	}
	if never {
		return Unknown
	}
	if age > staleAfter {
		return Idle
	}
	return OK
}

// Report returns the current judgement.
func (m *Monitor) Report(now time.Time) Report {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := Report{State: m.state(now), LatencyMs: m.rtt.Milliseconds(), HandshakeAge: -1}
	if !m.handshake.IsZero() {
		r.HandshakeAge = int64(now.Sub(m.handshake).Seconds())
	}
	if n := len(m.results); n > 0 {
		bad := 0
		for _, ok := range m.results {
			if !ok {
				bad++
			}
		}
		r.Loss = float64(bad) / float64(n)
	}
	return r
}

// Active reports whether the tunnel sent something in the last two
// minutes: only then is probing worth it (an idle phone should sleep).
func (m *Monitor) Active(now time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.observed && now.Sub(m.txAt) < 2*time.Minute
}

// ShouldReconnect is true once per reconnectGap while the tunnel is down;
// the caller then re-resolves the endpoint and re-opens its socket.
func (m *Monitor) ShouldReconnect(now time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state(now) != Down || now.Sub(m.lastRecon) < reconnectGap {
		return false
	}
	m.lastRecon = now
	m.fails = 0 // give the new socket a fair chance
	return true
}

// DNSProbe asks server (through dial, i.e. through the tunnel) for the
// root's NS records; any datagram back, even an error answer, proves the
// path works.
func DNSProbe(ctx context.Context, dial func(ctx context.Context, network, addr string) (net.Conn, error), server netip.Addr) (time.Duration, error) {
	c, err := dial(ctx, "udp", netip.AddrPortFrom(server, 53).String())
	if err != nil {
		return 0, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	q := new(dns.Msg)
	q.SetQuestion(".", dns.TypeNS)
	raw, err := q.Pack()
	if err != nil {
		return 0, err
	}
	start := time.Now()
	if _, err := c.Write(raw); err != nil {
		return 0, err
	}
	buf := make([]byte, 1500)
	if _, err := c.Read(buf); err != nil { // any datagram back will do
		return 0, err
	}
	return time.Since(start), nil
}
