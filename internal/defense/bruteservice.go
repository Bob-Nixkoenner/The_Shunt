package defense

import (
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"
)

// Brute force on real services. The scan detector (detect.go) only counts
// connections to ports nothing listens on; guessing passwords at a real
// sshd, a web login or a database does not show there. This counter takes
// the same input - the first packet of every new inbound TCP connection
// that the nft table logs (NFLOG group 5302) - for ports the port monitor
// lists as open (listening, reachable from the network, not loopback-only,
// not blocked by the inbound mode, not a decoy, not The Shunt's own). It
// never touches the service: nothing is delayed, answered or cut; it only
// counts and, when blocking is on and the source proved its address,
// blocks like any other brute-force finding.
//
// Many short connections of one source to one port within a window are a
// KindBruteService finding (medium; high at a high rate). "Short": the
// connection table (conntrack) is asked how many of the source's
// connections to that port are still established; those are not counted.
// A client that keeps its connections open (a browser's keep-alive pool,
// Syncthing, an SSH session) therefore never adds up, however long it runs.
//
// Thresholds, from the lab runs (docs/DEFENSE.md, "Brute force on real
// services"):
//   - R02 (2026-11-11): the scripted guesser (brute.py, one login per
//     connection, no parallel tasks, N=10) sent 19 SYNs to telnet and 31
//     to ssh (retransmissions and the port check included) within its 30 s
//     limit. That is the slowest scripted guessing seen; SvcBruteConns = 10
//     in SvcBruteWindow = 60 s catches it with room (the same number as the
//     scan detector's BruteConns).
//   - R01: the port scan sent at most 5 SYNs to any one port; it must stay
//     quiet here.
//   - Q01-Q03 (no attacker): at most 2 inbound SYNs per source and port.
//   - SvcBruteHigh = 60 per 60 s (one per second on average): hydra-like
//     tools run 4-16 tasks in parallel and reach that in seconds; a person
//     who mistypes a password never does.
//   - A web client that opens 6 connections in 10 s (the browser limit per
//     host) stays below SvcBruteConns.
const (
	SvcBruteWindow = 60 * time.Second
	SvcBruteConns  = 10
	SvcBruteHigh   = 60

	// memory caps: the counter is fed by strangers
	svcMaxEntries   = 2048 // (source, port) pairs in total
	svcMaxPortsPerS = 8    // ports counted per source
	svcProbeEvery   = 5 * time.Second
	svcProbeGlobal  = time.Second // at most one table read per second
	svcBuckets      = 60          // one per second of SvcBruteWindow
)

// ServiceFlows is what the connection table says about the connections of
// one source to one local port.
type ServiceFlows struct {
	Open      int  // established right now (not short, not counted)
	Handshake bool // at least one finished a TCP handshake (established or closing after one)
}

// ServiceProbe reads the connection table for src -> local port. ok=false:
// the table could not be read (then nothing is subtracted and no handshake
// is assumed).
type ServiceProbe func(src netip.Addr, port int) (f ServiceFlows, ok bool)

// WithServiceProbe sets how the connection table is read (Linux: conntrack).
func WithServiceProbe(p ServiceProbe) Option { return func(m *Manager) { m.svc.probe = p } }

type svcKey struct {
	src  netip.Addr
	port uint16
}

type svcEntry struct {
	buckets [svcBuckets]uint16
	base    int64 // unix second of the newest bucket
	last    time.Time
	fired   int // 0 none, 1 medium, 2 high (within firedAt+window)
	firedAt time.Time
	probed  time.Time
	banned  bool // block done (or not possible) for the current finding
	flows   ServiceFlows
	known   bool // flows came from a readable table
	service string
}

// add counts one connection at second sec.
func (e *svcEntry) add(sec int64) {
	e.roll(sec)
	if e.buckets[sec%svcBuckets] < ^uint16(0) {
		e.buckets[sec%svcBuckets]++
	}
}

// roll clears buckets older than the window when time moved on.
func (e *svcEntry) roll(sec int64) {
	if e.base == 0 || sec-e.base >= svcBuckets {
		e.buckets = [svcBuckets]uint16{}
	} else {
		for s := e.base + 1; s <= sec; s++ {
			e.buckets[s%svcBuckets] = 0
		}
	}
	if sec > e.base {
		e.base = sec
	}
}

func (e *svcEntry) count() int {
	n := 0
	for _, b := range e.buckets {
		n += int(b)
	}
	return n
}

type svcState struct {
	mu        sync.Mutex
	m         map[svcKey]*svcEntry
	perSrc    map[netip.Addr]int
	dropped   uint64
	probe     ServiceProbe
	lastProbe time.Time
}

func (s *svcState) reset() {
	s.mu.Lock()
	s.m, s.perSrc = nil, nil
	s.mu.Unlock()
}

func (s *svcState) size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.m)
}

func (s *svcState) deleteLocked(k svcKey) {
	delete(s.m, k)
	if s.perSrc[k.src]--; s.perSrc[k.src] <= 0 {
		delete(s.perSrc, k.src)
	}
}

// pruneLocked drops pairs without a connection in the window.
func (s *svcState) pruneLocked(now time.Time) {
	for k, e := range s.m {
		if now.Sub(e.last) > SvcBruteWindow {
			s.deleteLocked(k)
		}
	}
}

func (s *svcState) prune(now time.Time) {
	s.mu.Lock()
	s.pruneLocked(now)
	s.mu.Unlock()
}

// svcDecision is what one counted connection leads to (worked out under
// the lock, carried out after it).
type svcDecision struct {
	report  bool
	sev     Severity
	conns   int
	short   int
	open    int
	hs      string // yes, no, unknown
	ban     bool
	service string
}

// ObserveService counts one new inbound TCP connection (its first packet,
// a bare SYN) from src to a real open local port. service names the program
// that listens (may be ""). The caller has already left out replies to this
// machine's own connections, decoy ports and ports that are not open.
func (m *Manager) ObserveService(src netip.Addr, port int, proto, service string) {
	src = src.Unmap()
	if proto != "tcp" || port <= 0 || port > 65535 || !src.IsValid() || !m.feature(FeatBrute).Watch {
		return
	}
	now := m.now()
	// own devices at every trust step, the never list (gateway, DNS
	// servers, tunnel endpoints, user entries), loopback and this machine's
	// own addresses never count
	if src.IsLoopback() || src.IsUnspecified() || src.IsMulticast() || m.never.Contains(src) ||
		(m.ownAddr != nil && m.ownAddr(src)) || m.ignore.Match(src, port) || m.ignore.Trust(src, port, now) != "" {
		return
	}
	d, ok := m.svc.step(m.log, src, port, service, now)
	if !ok {
		return
	}
	if m.grace > 0 && now.Sub(m.started) < m.grace {
		return // state is still being rebuilt after the start: observe only
	}
	if d.report {
		detail := fmt.Sprintf("service=%s conns=%d short=%d open=%d window=%ds handshake=%s",
			serviceLabel(d.service), d.conns, d.short, d.open, int(SvcBruteWindow/time.Second), d.hs)
		if d.hs != "yes" && m.feature(FeatBrute).Block {
			detail += " block=waits_for_handshake"
		}
		m.Report(Event{Kind: KindBruteService, Severity: d.sev, Src: src.String(), Port: port, Proto: "tcp", Detail: detail})
	}
	if d.ban {
		// the connection table showed a finished handshake with the real
		// service: the address is not forged
		if reason, waited := m.ver.confirm(src, now); waited {
			m.banNow(src, reason, "confirmed=handshake")
		}
		m.maybeBan(src, KindBruteService, FeatBrute)
	}
}

// serviceLabel keeps the program name short and printable.
func serviceLabel(s string) string {
	if s == "" {
		return "unknown"
	}
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s) && len(b) < 32; i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_', c == '.', c == ':':
			b = append(b, c)
		default:
			b = append(b, '_')
		}
	}
	return string(b)
}

// step counts the connection and decides. ok=false: nothing to do.
func (s *svcState) step(log *slog.Logger, src netip.Addr, port int, service string, now time.Time) (svcDecision, bool) {
	k := svcKey{src, uint16(port)}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m, s.perSrc = map[svcKey]*svcEntry{}, map[netip.Addr]int{}
	}
	e := s.m[k]
	if e == nil {
		if len(s.m) >= svcMaxEntries || s.perSrc[src] >= svcMaxPortsPerS {
			s.pruneLocked(now)
			if len(s.m) >= svcMaxEntries || s.perSrc[src] >= svcMaxPortsPerS {
				s.dropped++
				return svcDecision{}, false
			}
		}
		e = &svcEntry{}
		s.m[k] = e
		s.perSrc[src]++
	}
	if service != "" {
		e.service = service
	}
	e.last = now
	e.add(now.Unix())
	if e.fired > 0 && now.Sub(e.firedAt) > SvcBruteWindow {
		e.fired, e.banned = 0, false
	}
	n := e.count()
	if n < SvcBruteConns {
		return svcDecision{}, false
	}
	// candidate: ask the connection table (rate limited: once per pair
	// every 5 s, once per second over all pairs)
	wantsProbe := e.fired == 0 || (n >= SvcBruteHigh && e.fired < 2) || !e.banned
	if !wantsProbe {
		return svcDecision{}, false
	}
	if s.probe != nil && now.Sub(e.probed) >= svcProbeEvery && now.Sub(s.lastProbe) >= svcProbeGlobal {
		e.probed, s.lastProbe = now, now
		probe := s.probe
		s.mu.Unlock()
		var f ServiceFlows
		ok := false
		// a bug in the table reader must not leave the lock taken or end
		// the packet reader: caught here, counted as unreadable
		if Guard(log, "service connection table", func() { f, ok = probe(src, port) }) {
			f, ok = ServiceFlows{}, false
		}
		s.mu.Lock()
		if e2 := s.m[k]; e2 != e { // dropped meanwhile (network change, prune)
			return svcDecision{}, false
		}
		e.flows, e.known = f, ok
	} else if s.probe != nil && e.probed.IsZero() {
		return svcDecision{}, false // never read yet: the next connection asks
	}
	// between reads the last answer stands
	flows, known := e.flows, e.known
	short := n
	if known {
		short = max(0, n-flows.Open)
	}
	level := 0
	switch {
	case short >= SvcBruteHigh:
		level = 2
	case short >= SvcBruteConns:
		level = 1
	}
	if level == 0 {
		return svcDecision{}, false
	}
	d := svcDecision{conns: n, short: short, open: flows.Open, service: e.service, hs: "unknown"}
	if known {
		d.hs = "no"
		if flows.Handshake {
			d.hs = "yes"
		}
	}
	if level > e.fired {
		d.report = true
		d.sev = SevMedium
		if level == 2 {
			d.sev = SevHigh
		}
		if e.fired == 0 {
			e.firedAt = now
		}
		e.fired = level
	}
	if !e.banned && known && flows.Handshake {
		d.ban, e.banned = true, true
	}
	return d, d.report || d.ban
}
