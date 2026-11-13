package defense

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Manager implements Engine.
type Manager struct {
	offenders map[string]offender // escalation memory, guarded by mu
	log       *slog.Logger
	ring      *Ring
	therm     *Thermo
	bans      *Bans
	rep       *Reputation
	det       *Detector
	never     *NeverSet
	ignore    IgnoreSet
	names     *NameCache
	started   time.Time     // when the manager began (start grace)
	grace     time.Duration // after start, scans and brute force are only observed
	ver       verifier
	dec       *Decoys
	rpts      *Reports
	dns       dnsState
	conn      connState
	chain     chainState
	svc       svcState
	now       func() time.Time

	syncMu sync.Mutex // serialises decoy start/stop; never taken with mu held
	mu     sync.Mutex
	cfg    Config
	key    string
	class  Class
	expo   Exposure
	out    *OutsideResult

	aggMu      sync.Mutex
	agg        map[aggKey]*aggEntry
	aggDropped int

	onEvent func(Event, Class)    // evidence log hook (WithEventHook)
	ownAddr func(netip.Addr) bool // this machine's addresses (WithOwnAddr)

	stop     context.CancelFunc
	done     chan struct{}
	closeOne sync.Once
}

// Option customises NewManager.
type Option func(*Manager)

// WithListen sets how decoy listeners are opened.
func WithListen(f ListenFunc) Option { return func(m *Manager) { m.dec.Listen = f } }

// WithStartGrace makes scan and brute-force findings in the first d after the
// start only observed: not reported, not blocked. Right after a restart the
// connection state of this machine is being rebuilt, answers to its own
// connections look like strangers.
func WithStartGrace(d time.Duration) Option { return func(m *Manager) { m.grace = d } }

// WithBanHooks sets the callbacks for blocks and unblocks (firewall).
func WithBanHooks(onBan, onUnban func(Ban)) Option {
	return func(m *Manager) { m.bans.OnBan, m.bans.OnUnban = onBan, onUnban }
}

// WithOwnAddr tells the manager which addresses belong to this machine; they
// are never blocked (a forged source address must not lock out the host
// itself).
func WithOwnAddr(f func(netip.Addr) bool) Option { return func(m *Manager) { m.ownAddr = f } }

// Bannable reports whether a can be blocked at all: a unicast address that
// is not this machine's own and not on the never-list. Multicast,
// unspecified and the IPv4 broadcast address only ever appear as forged
// sources. (Loopback stays allowed: the kernel drops it on real interfaces
// as a martian and the nft chain skips lo, so a ban there is harmless; the
// decoy tests rely on it.)
func (m *Manager) Bannable(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || a.IsUnspecified() || a.IsMulticast() ||
		a.IsInterfaceLocalMulticast() || a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return false
	}
	if a.Is4() && a.As4()[0] == 0 { // 0.0.0.0/8: "this network", never a real source
		return false
	}
	if m.never.Contains(a) {
		return false
	}
	return m.ownAddr == nil || !m.ownAddr(a)
}

// WithSSHHostKey keeps the ssh decoy's host key in this file (created with
// mode 0600 on first use). Without it the key lives in memory only.
func WithSSHHostKey(path string) Option { return func(m *Manager) { m.dec.HostKeyPath = path } }

// WithBaitFile keeps the lock credentials of the bait files in this file
// (created with mode 0600 on first use, see bait.go). Without it they live in
// memory only and change with every start.
func WithBaitFile(path string) Option { return func(m *Manager) { m.dec.BaitPath = path } }

// WithReportFile keeps the per-network reports in this file (mode 0600).
// Without it they stay in memory.
func WithReportFile(path string) Option { return func(m *Manager) { m.rpts = NewReports(path) } }

// WithClock replaces the clock (tests).
func WithClock(now func() time.Time) Option {
	return func(m *Manager) {
		m.now = now
		m.ring.now, m.therm.now, m.bans.now, m.rep.now, m.det.now = now, now, now, now, now
	}
}

// WithRingSize sets how many events are kept (default 1000).
func WithRingSize(n int) Option { return func(m *Manager) { m.ring = NewRing(n) } }

// NewManager returns an idle manager (disabled until Configure sets Enabled).
func NewManager(log *slog.Logger, opts ...Option) *Manager {
	if log == nil {
		log = slog.Default()
	}
	m := &Manager{log: log, ring: NewRing(1000), therm: NewThermo(), bans: NewBans(),
		rpts: NewReports(""), agg: map[aggKey]*aggEntry{}, rep: NewReputation(), names: NewNameCache(), never: &NeverSet{}, now: time.Now, class: ClassUnknown, cfg: DefaultConfig()}
	m.cfg.Enabled = false
	m.det = NewDetector(DetectConfig{}, m.never)
	m.det.OnFound = m.found
	m.dec = NewDecoys(nil, m.decoyHit)
	m.dec.SSHDelay = sshDefaultDelay
	m.dec.Log = log
	for _, o := range opts {
		o(m)
	}
	m.started = m.now()
	ctx, cancel := context.WithCancel(context.Background())
	m.stop, m.done = cancel, make(chan struct{})
	go m.loop(ctx)
	return m
}

// Reputation gives access to the lists (for the updater).
func (m *Manager) Reputation() *Reputation { return m.rep }

// SetNever sets the automatic never-block list (gateway, DNS, portal).
func (m *Manager) SetNever(p []netip.Prefix) { m.never.SetAuto(p) }

func (m *Manager) loop(ctx context.Context) {
	defer close(m.done)
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			Guard(m.log, "defense housekeeping", m.tick)
		}
	}
}

// tick is the 30 s housekeeping: expired bans, old list entries, folded
// events, report files.
func (m *Manager) tick() {
	for _, b := range m.bans.Prune() {
		m.Report(Event{Kind: KindUnban, Severity: SevInfo, Src: b.Src, Detail: "expired"})
	}
	m.rep.Prune()
	m.ver.prune(m.now())
	m.chain.prune(m.now())
	m.svc.prune(m.now())
	m.flushAgg(false)
	if err := m.rpts.Flush(); err != nil {
		m.log.Debug("defense: report file", "err", err)
	}
	if err := m.flushFirstSeen(); err != nil {
		m.log.Debug("defense: first-contact file", "err", err)
	}
}

func (m *Manager) feature(name string) Feature {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.featureLocked(name)
}

// featureLocked is featureOf with the network class applied. Caller holds mu.
func (m *Manager) featureLocked(name string) Feature { return effFeature(m.cfg, m.class, name) }

// UnsafeBlockOn reports whether unsafe networks switch the blocks on.
func (c Config) UnsafeBlockOn() bool { return c.UnsafeBlock == nil || *c.UnsafeBlock }

// blockCapable are the features that can block at all.
var blockCapable = map[string]bool{FeatScan: true, FeatBrute: true, FeatReputation: true, FeatDNSRebind: true}

// effFeature is featureOf with the network class applied: in an unsafe
// network the features that can block do (unless unsafe_block is off).
func effFeature(c Config, class Class, name string) Feature {
	f := featureOf(c, name)
	if f.Watch && blockCapable[name] && class.Normalize() == ClassUnsafe && c.UnsafeBlockOn() {
		f.Block = true
	}
	return f
}

func featureOf(c Config, name string) Feature {
	if !c.Enabled {
		return Feature{}
	}
	f := c.Features[name]
	if !f.Watch {
		return Feature{}
	}
	return f
}

// Configure applies a new configuration and restarts the decoys.
func (m *Manager) Configure(cfg Config) {
	if cfg.BanSeconds <= 0 {
		cfg.BanSeconds = 3600
	}
	if cfg.BanSeconds2 == 0 {
		cfg.BanSeconds2 = DefaultBanSeconds2
	}
	if cfg.BanSeconds3 == 0 {
		cfg.BanSeconds3 = BanForever
	}
	m.mu.Lock()
	m.cfg = cfg
	m.never.SetConfig(ParsePrefixes(cfg.Never))
	m.ignore.Set(cfg.Ignore)
	key, class := m.key, m.class
	watchDNS := featureOf(cfg, FeatDNS).Watch
	m.mu.Unlock()
	if cfg.Enabled && key != "" {
		m.rpts.Enter(key, class, m.now(), watchDNS)
	}
	m.syncDecoys()
}

// SetNetwork records the network; a new key resets the counters.
func (m *Manager) SetNetwork(key string, class Class) {
	class = class.Normalize()
	m.mu.Lock()
	changed := key != m.key
	m.key, m.class = key, class
	m.therm.SetNetwork(key, class)
	enabled := m.cfg.Enabled
	watchDNS := featureOf(m.cfg, FeatDNS).Watch
	m.mu.Unlock()
	if enabled {
		m.rpts.Enter(key, class, m.now(), watchDNS)
	}
	m.syncDecoys()
	if changed {
		m.forgetDNS()
		m.forgetConns()
		m.chain.reset()
		m.svc.reset()
		m.names.Forget()
	}
	if changed && enabled {
		m.Report(Event{Kind: KindNetEnter, Severity: SevInfo, Detail: "class=" + string(class) + " net=" + NetID(key)})
	}
}

// NetID is the short label of a network in the evidence log: the first 8
// characters of its (already hashed) key. It lets an export pick the lines of
// one network without the log ever holding a name.
func NetID(key string) string {
	if len(key) > 8 {
		key = key[:8]
	}
	return key
}

// syncDecoys starts or stops decoys to match config and class. Handlers
// call back into the manager, so mu must not be held while stopping.
func (m *Manager) syncDecoys() {
	m.syncMu.Lock()
	defer m.syncMu.Unlock()
	m.mu.Lock()
	cfg, class, expo := m.cfg, m.class, m.expo
	m.mu.Unlock()
	if f := featureOf(cfg, FeatDecoy); !f.Watch || !class.Decoys() || (expo.Any() && !cfg.DecoysWhenExposed) {
		m.dec.Stop()
		return
	}
	m.dec.Start(cfg.DecoyPorts, DecoyOptions{
		Tarpit: featureOf(cfg, FeatTarpit).Watch,
		Cowrie: featureOf(cfg, FeatCowrie).Watch,
	})
}

// Report adds an event (also from outside). It is dropped while disabled.
func (m *Manager) Report(ev Event) {
	m.mu.Lock()
	enabled := m.cfg.Enabled
	m.mu.Unlock()
	if !enabled {
		return
	}
	if ignoredKind(ev.Kind) {
		if a, err := netip.ParseAddr(ev.Src); err == nil && m.ignore.Match(a, ev.Port) {
			return
		}
		if a, err := netip.ParseAddr(ev.Src); err == nil {
			ev.Trust = m.ignore.Trust(a, ev.Port, m.now())
		}
	}
	// tempo detection sees only what passed the ignore list; a finished
	// chain is reported after this event
	if h, ok := m.chain.step(ev, m.now()); ok {
		defer m.chainFound(h)
	}
	if m.fold(ev) {
		// folded: counts for heat and the report, but takes no ring slot
		ev.Time = m.now()
		m.therm.Add(ev)
		m.rpts.Note(ev, m.therm.Heat())
		return
	}
	ev = m.ring.Add(ev)
	m.therm.Add(ev)
	m.rpts.Note(ev, m.therm.Heat())
	m.emitEvent(ev)
}

// Observe feeds one connection attempt into scan/brute detection and the
// reputation check.
func (m *Manager) Observe(src netip.Addr, port int, proto string, ok bool) {
	st := StateOK
	if !ok {
		st = StateREJ
	}
	m.ObserveState(src, port, proto, st)
}

// ObserveState is Observe with a Zeek-style outcome (S0/REJ/OK).
func (m *Manager) ObserveState(src netip.Addr, port int, proto string, st ConnState) {
	if (m.feature(FeatScan).Watch || m.feature(FeatBrute).Watch) && !m.ignore.Match(src, port) {
		m.det.ObserveState(src, port, proto, st)
	}
	m.CheckPeer(src, port, proto)
}

// CheckPeer reports and (if set) blocks an address that is on a bad list.
func (m *Manager) CheckPeer(a netip.Addr, port int, proto string) bool {
	f := m.feature(FeatReputation)
	if !f.Watch {
		return false
	}
	name, hit := m.rep.Lookup(a)
	if !hit {
		return false
	}
	m.Report(Event{Kind: KindReputation, Severity: SevHigh, Src: a.Unmap().String(), Port: port, Proto: proto, Detail: "list=" + name})
	if QualityList(name) {
		m.maybeBan(a, KindReputation, FeatReputation)
	}
	return true
}

func (m *Manager) decoyHit(h Hit) {
	// every decoy hit comes from an accepted connection: the source
	// finished a TCP handshake, so its address is not forged (see verify.go)
	if src := h.Src.Unmap(); src.IsValid() {
		if reason, waited := m.ver.confirm(src, m.now()); waited {
			m.banNow(src, reason, "confirmed=handshake")
		}
	}
	if h.JA3 != "" {
		m.ja3Seen(h)
		return
	}
	m.Report(Event{Kind: h.Kind, Severity: h.Sev, Src: h.Src.String(), Port: h.Port, Proto: "tcp", Detail: h.Detail})
	switch h.Kind {
	case KindDecoyHit:
		if !h.Extra {
			m.Observe(h.Src, h.Port, "tcp", false)
		}
	case KindBait:
		// someone read a bait file and uses what it found: block at once
		// (the source finished a handshake, nothing waits) when blocking of
		// login attempts is on; ignored devices never get here
		if !m.ignore.Match(h.Src.Unmap(), h.Port) {
			m.maybeBan(h.Src, KindBait, FeatBrute)
		}
	}
}

// ja3Seen reports a TLS fingerprint; a hit on the JA3 list is severity high
// and can ban like any bad-reputation peer.
func (m *Manager) ja3Seen(h Hit) {
	ev := Event{Kind: h.Kind, Severity: h.Sev, Src: h.Src.String(), Port: h.Port, Proto: "tcp", Detail: h.Detail}
	if f := m.feature(FeatReputation); f.Watch {
		if name, bad := m.rep.LookupJA3(h.JA3); bad {
			ev.Kind, ev.Severity, ev.Detail = KindReputation, SevHigh, "list="+name+" ja3="+h.JA3
			m.Report(ev)
			if QualityList(name) {
				m.maybeBan(h.Src, KindReputation, FeatReputation)
			}
			return
		}
	}
	m.Report(ev)
}

func (m *Manager) found(f Finding) {
	if m.grace > 0 && m.now().Sub(m.started) < m.grace {
		return // state is still being rebuilt after the start: observe only
	}
	sev, feat := SevHigh, FeatScan
	if f.Kind == KindBruteForce {
		sev, feat = SevMedium, FeatBrute
	}
	detail := f.Detail
	if m.banWaits(f.Src, feat) {
		detail += " block=waits_for_handshake"
	}
	m.Report(Event{Kind: f.Kind, Severity: sev, Src: f.Src.String(), Detail: detail})
	m.maybeBan(f.Src, f.Kind, feat)
}

// banWaits reports whether a block of src for feat would be held back
// because the source address is not confirmed by a handshake.
func (m *Manager) banWaits(src netip.Addr, feat string) bool {
	m.mu.Lock()
	f := m.featureLocked(feat)
	unverified := m.cfg.BanUnverified
	m.mu.Unlock()
	src = src.Unmap()
	return f.Watch && f.Block && !unverified && m.Bannable(src) && !m.ver.confirmed(src, m.now())
}

// maybeBan blocks src if the feature's Block switch is on and src is not on
// the never-list.
func (m *Manager) maybeBan(src netip.Addr, reason Kind, feat string) {
	m.mu.Lock()
	f := m.featureLocked(feat)
	unverified := m.cfg.BanUnverified
	m.mu.Unlock()
	src = src.Unmap()
	if !f.Watch || !f.Block || !m.Bannable(src) || (reason != KindReputation && m.ignore.TrustAny(src, m.now()) != "") {
		return
	}
	// Findings built from packets alone (scan, brute force) wait for a
	// handshake: the source address may be forged. A reputation hit names
	// an address that is on a bad list anyway, so it is not held back.
	if reason != KindReputation && !unverified && !m.ver.confirmed(src, m.now()) {
		m.ver.hold(src, reason, m.now())
		return
	}
	m.addBan(src, reason, 0, "")
}

// banNow carries out a block that waited for the handshake.
func (m *Manager) banNow(src netip.Addr, reason Kind, note string) {
	feat := FeatScan
	if reason == KindBruteForce || reason == KindBruteService {
		feat = FeatBrute
	}
	m.mu.Lock()
	f := m.featureLocked(feat)
	m.mu.Unlock()
	if !f.Watch || !f.Block || !m.Bannable(src) || m.ignore.TrustAny(src, m.now()) != "" {
		return
	}
	m.addBan(src, reason, 0, note)
}

// escalate returns the block level of target: 1 for a first block, higher for
// a source that was blocked before (within offenderMemory). A target that is
// blocked right now keeps its level. Manual blocks do not escalate.
func (m *Manager) escalate(target string, manual bool) int {
	if manual {
		return 1
	}
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.offenders == nil {
		m.offenders = map[string]offender{}
	}
	o := m.offenders[target]
	if !o.last.IsZero() && now.Sub(o.last) > offenderMemory {
		o = offender{}
	}
	if m.bans.Has(target) {
		if o.n < 1 {
			o.n = 1
		}
		return o.n
	}
	o.n++
	o.last = now
	if len(m.offenders) >= maxOffenders {
		var oldest string
		var at time.Time
		for k, v := range m.offenders {
			if oldest == "" || v.last.Before(at) {
				oldest, at = k, v.last
			}
		}
		delete(m.offenders, oldest)
	}
	m.offenders[target] = o
	return o.n
}

type offender struct {
	n    int
	last time.Time
}

// addBan blocks src, or its whole range while exposed (see banTarget). d 0
// means: the configured time for the source's escalation level.
func (m *Manager) addBan(src netip.Addr, reason Kind, d time.Duration, note string) {
	target := m.banTarget(src)
	if target == "" {
		return
	}
	if p, err := netip.ParsePrefix(target); err == nil {
		for _, s := range m.bans.InRange(p) { // the range replaces its single entries
			m.bans.Remove(s)
		}
	}
	level, perm := 1, false
	if d <= 0 {
		level = m.escalate(target, reason == KindManual)
		m.mu.Lock()
		d, perm = m.cfg.BanFor(level)
		m.mu.Unlock()
	}
	if b, isNew := m.bans.AddLevel(target, reason, d, perm, level); isNew {
		detail := "reason=" + string(reason)
		if level > 1 {
			detail += fmt.Sprintf(" level=%d", level)
		}
		if b.Permanent {
			detail += " permanent"
		}
		if note != "" {
			detail += " " + note
		}
		m.Report(Event{Kind: KindBan, Severity: SevLow, Src: b.Src, Detail: detail})
	}
}

// ErrNeverBan is returned when a manual block hits the never-list.
var ErrNeverBan = errors.New("address is on the never-block list (gateway, DNS, portal or your own list)")

// ErrNotBannable is returned for a manual block of an address that cannot be
// a remote source (own, multicast, broadcast, unspecified).
var ErrNotBannable = errors.New("address cannot be blocked (own address, multicast or broadcast)")

// Ban blocks src by hand for the configured time.
func (m *Manager) Ban(src string) error {
	a, err := netip.ParseAddr(strings.TrimSpace(src))
	if err != nil {
		return err
	}
	a = a.Unmap()
	m.mu.Lock()
	enabled := m.cfg.Enabled
	m.mu.Unlock()
	if !enabled {
		return errors.New("defense is off")
	}
	if m.never.Contains(a) {
		return ErrNeverBan
	}
	if !m.Bannable(a) {
		return ErrNotBannable
	}
	m.addBan(a, KindManual, 0, "")
	return nil
}

// Unban lifts one block ("" = all).
func (m *Manager) Unban(src string) {
	for _, b := range m.bans.Remove(src) {
		m.Report(Event{Kind: KindUnban, Severity: SevInfo, Src: b.Src, Detail: "manual"})
	}
}

// Events returns events with Seq > since.
func (m *Manager) Events(since uint64) EventsResponse {
	r := m.ring.Events(since)
	r.Names = m.names.For(eventSrcs(r.Events))
	return r
}

// EventsFor returns the events of one source address (all kinds), oldest
// first. src is normalised (IPv4-mapped form, case); anything that is no
// address matches nothing.
func (m *Manager) EventsFor(src string) EventsResponse {
	a, err := netip.ParseAddr(src)
	if err != nil {
		return EventsResponse{Events: []Event{}, LastSeq: m.ring.LastSeq()}
	}
	r := m.ring.EventsFor(a.Unmap().String())
	r.Names = m.names.For([]string{a.String()})
	return r
}

// Reports returns the per-network reports (export = redacted copy).
func (m *Manager) Reports(export bool) ReportsResponse { return m.rpts.List(export) }

// Status returns the current state.
func (m *Manager) Status() Status {
	m.mu.Lock()
	cfg, class, expo := m.cfg, m.class, m.expo
	m.mu.Unlock()
	heat := m.therm.Heat()
	return Status{Enabled: cfg.Enabled, Class: class, Exposed: expo, Outside: m.outside(), Heat: heat, Level: LevelFor(heat),
		Decoys: m.dec.Ports(), Bans: m.bans.List(), Counts: m.therm.Counts(),
		LastSeq: m.ring.LastSeq(), Config: cfg, Sources: m.sourceInfo(cfg)}
}

// sourceInfo reports every list with its switch and last download result.
func (m *Manager) sourceInfo(cfg Config) []SourceInfo {
	on := map[string]bool{}
	for _, s := range SourcesFor(cfg.ReputationSources, cfg.ReputationOff) {
		on[s.Name] = true
	}
	var out []SourceInfo
	now := m.rep.now()
	for _, n := range []string{"feodo", "sslbl", "sslbl_ja3", "et_compromised"} {
		st := m.rep.Stat(n)
		ttl := time.Duration(0)
		if s, ok := OptionalSources[n]; ok {
			ttl = s.TTL
		} else {
			for _, d := range DefaultSources {
				if d.Name == n {
					ttl = d.TTL
				}
			}
		}
		// expired: the list is no longer used for lookups
		exp := on[n] && ((!st.Updated.IsZero() && now.After(st.Updated.Add(ttl))) || (st.Updated.IsZero() && st.Error != ""))
		out = append(out, SourceInfo{Name: n, On: on[n], Entries: st.Entries, Updated: st.Updated, Error: st.Error, Expired: exp, Quality: QualityList(n)})
	}
	return append(out, SourceInfo{Name: SpamhausDROP, Unavailable: true})
}

// Close stops everything. It is safe to call twice.
func (m *Manager) Close() {
	m.closeOne.Do(func() {
		m.stop()
		<-m.done
		m.dec.Stop()
		_ = m.rpts.Flush()
		_ = m.flushFirstSeen()
	})
}

var _ Engine = (*Manager)(nil)

// Watching reports whether feature name is switched on for detection (and
// the defense as a whole is enabled).
func (m *Manager) Watching(name string) bool { return m.feature(name).Watch }

// SetOutside records the result of an outside check (shown in the status)
// and reports it: severity high when ports answer from the internet.
func (m *Manager) SetOutside(r OutsideResult) {
	m.mu.Lock()
	m.out = &r
	m.mu.Unlock()
	var parts []string
	for _, c := range r.Checks {
		switch {
		case c.Error != "":
			parts = append(parts, c.Family+"=error")
		case len(c.Open) == 0:
			parts = append(parts, c.Family+"=none")
		default:
			l := make([]string, len(c.Open))
			for i, p := range c.Open {
				l[i] = strconv.Itoa(p)
			}
			parts = append(parts, c.Family+"="+strings.Join(l, ","))
		}
	}
	sev := SevInfo
	if r.OpenCount() > 0 {
		sev = SevHigh
	}
	m.Report(Event{Kind: KindOutside, Severity: sev, Detail: "open " + strings.Join(parts, " ")})
}

func (m *Manager) outside() *OutsideResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.out == nil {
		return nil
	}
	c := *m.out
	return &c
}
