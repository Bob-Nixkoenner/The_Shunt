package defense

import (
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Limits that apply while the uplink has a public address ("exposed"): the
// machine is then scanned and attacked all day, so everything that grows
// with the number of sources is capped.
const (
	// RangeBanSources: once this many single addresses of one /24 (IPv4) or
	// /64 (IPv6) are blocked, the whole range is blocked instead.
	RangeBanSources = 4
	// AggWindow: events of the same kind and source inside this time are
	// folded into the first one plus a "more=N" summary.
	AggWindow = 30 * time.Second
	// AggMax caps the folding table; beyond it events are only counted.
	AggMax = 2048
)

type aggKey struct {
	kind Kind
	src  string
}

type aggEntry struct {
	first Event
	last  time.Time
	more  int
}

// aggregatable says which kinds are folded while exposed. Rare, important
// findings (spoofing, hijack, certificate, exposure itself) always show.
func aggregatable(k Kind) bool {
	switch k {
	case KindDecoyHit, KindTarpit, KindCowrie, KindScan, KindBruteForce, KindReputation, KindFirstSeen, KindObservation:
		return true
	}
	return false
}

// SetExposure records whether the uplink has a public address. A change to
// "exposed" (or a change of the inbound mode while exposed) raises the
// event "exposed" (severity high); the decoys follow the new state.
func (m *Manager) SetExposure(e Exposure) {
	if e.Inbound == "" {
		e.Inbound = "off"
	}
	m.mu.Lock()
	old := m.expo
	m.expo = e
	enabled := m.cfg.Enabled
	m.mu.Unlock()
	m.syncDecoys()
	if !e.Any() {
		m.flushAgg(true)
		return
	}
	if enabled && (!old.Any() || old != e) {
		fam := []string{}
		if e.V4 {
			fam = append(fam, "v4")
		}
		if e.V6 {
			fam = append(fam, "v6")
		}
		m.Report(Event{Kind: KindExposed, Severity: SevHigh,
			Detail: "inbound=" + e.Inbound + " public=" + strings.Join(fam, ",")})
	}
}

func (m *Manager) exposure() Exposure {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.expo
}

// fold decides whether ev is folded into an earlier one (true: do not store
// it). The first event of a kind and source always goes through.
func (m *Manager) fold(ev Event) bool {
	if !m.exposure().Any() || !aggregatable(ev.Kind) || ev.Src == "" {
		return false
	}
	now := m.now()
	k := aggKey{ev.Kind, ev.Src}
	m.aggMu.Lock()
	var summary *Event
	e, ok := m.agg[k]
	switch {
	case ok && now.Sub(e.first.Time) < AggWindow:
		e.more++
		e.last = now
		m.aggMu.Unlock()
		return true
	case ok:
		summary = summaryOf(e)
		delete(m.agg, k)
	}
	if len(m.agg) >= AggMax {
		m.aggDropped++
		m.aggMu.Unlock()
		return true
	}
	ev.Time = now
	m.agg[k] = &aggEntry{first: ev, last: now}
	m.aggMu.Unlock()
	if summary != nil {
		m.ring.Add(*summary)
	}
	return false
}

func summaryOf(e *aggEntry) *Event {
	if e.more == 0 {
		return nil
	}
	s := e.first
	s.Seq, s.Time = 0, e.last
	s.Detail = "more=" + strconv.Itoa(e.more)
	return &s
}

// flushAgg writes the summaries of folded events whose window ended (all of
// them with force). Called every 30 seconds and when the exposure ends.
func (m *Manager) flushAgg(force bool) {
	now := m.now()
	m.aggMu.Lock()
	var out []Event
	for k, e := range m.agg {
		if force || now.Sub(e.first.Time) >= AggWindow {
			if s := summaryOf(e); s != nil {
				out = append(out, *s)
			}
			delete(m.agg, k)
		}
	}
	if m.aggDropped > 0 && (force || len(m.agg) < AggMax) {
		out = append(out, Event{Kind: KindObservation, Severity: SevInfo, Time: now, Detail: "more=" + strconv.Itoa(m.aggDropped)})
		m.aggDropped = 0
	}
	m.aggMu.Unlock()
	for _, ev := range out {
		m.ring.Add(ev)
	}
}

// banTarget decides what to block for src while exposed: a covered address
// needs nothing, and when RangeBanSources addresses of one range are
// blocked, the range is blocked (unless it contains a never-block entry).
// It returns the entry to ban ("" = nothing to do).
func (m *Manager) banTarget(src netip.Addr) string {
	if !m.exposure().Any() {
		return src.String()
	}
	if m.bans.Covered(src) {
		return ""
	}
	r := RangeOf(src)
	if m.never.Overlaps(r) {
		return src.String()
	}
	singles := m.bans.InRange(r)
	have := false
	for _, s := range singles {
		have = have || s == src.String()
	}
	n := len(singles)
	if !have {
		n++
	}
	if n < RangeBanSources {
		return src.String()
	}
	return r.String()
}
