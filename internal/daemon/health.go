package daemon

import (
	"context"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/dnsproxy"
	"github.com/Bob-Nixkoenner/the_shunt/internal/health"
	"github.com/miekg/dns"
)

// checkHealth feeds every tunnel's counters to its health monitor and,
// for tunnels in use, sends one DNS query through the tunnel's own DNS
// route (also encrypted upstreams), which gives the latency. Runs outside
// d.mu: a probe may take seconds.
func (d *Daemon) checkHealth() {
	type job struct {
		name string
		mon  *health.Monitor
		ups  []dnsproxy.Upstream
		hs   time.Time
		rx   int64
		tx   int64
		ok   bool
	}
	d.mu.Lock()
	if d.healthBusy {
		d.mu.Unlock()
		return
	}
	d.healthBusy = true
	if d.health == nil {
		d.health = map[string]*health.Monitor{}
	}
	var jobs []job
	for name, t := range d.tunnels {
		m := d.health[name]
		if m == nil {
			m = &health.Monitor{}
			d.health[name] = m
		}
		j := job{name: name, mon: m, ups: d.dnsUps["tunnel:"+name]}
		if peers, err := t.Status(); err == nil {
			j.ok = true
			for _, p := range peers {
				if p.LastHandshake.After(j.hs) {
					j.hs = p.LastHandshake
				}
				j.rx += p.RxBytes
				j.tx += p.TxBytes
			}
		}
		jobs = append(jobs, j)
	}
	for name := range d.health { // removed tunnels
		if _, ok := d.tunnels[name]; !ok {
			delete(d.health, name)
		}
	}
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		d.healthBusy = false
		d.mu.Unlock()
	}()

	for _, j := range jobs {
		now := time.Now()
		before := j.mon.Report(now).State
		if j.ok {
			j.mon.Observe(j.hs, j.rx, j.tx, now)
		}
		if j.mon.Active(now) && len(j.ups) > 0 {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			q := new(dns.Msg)
			q.SetQuestion(".", dns.TypeNS)
			start := time.Now()
			_, err := j.ups[0].Exchange(ctx, q)
			cancel()
			j.mon.Probed(time.Since(start), err)
		}
		r := j.mon.Report(time.Now())
		if r.State != before && before != health.Unknown {
			d.Log.Info("tunnel health", "tunnel", j.name, "state", r.State, "latency_ms", r.LatencyMs, "was", before)
		}
		if j.mon.ShouldReconnect(time.Now()) {
			// the watchdog re-resolves stale endpoints and re-creates dead
			// tunnels; make it run now
			d.Log.Warn("tunnel gets no answers", "tunnel", j.name)
			d.mu.Lock()
			d.watchdogLocked()
			d.mu.Unlock()
		}
	}
}

// healthReport returns the report of a tunnel, or nil (d.mu held).
func (d *Daemon) healthReport(name string) *health.Report {
	if m := d.health[name]; m != nil {
		r := m.Report(time.Now())
		return &r
	}
	return nil
}
