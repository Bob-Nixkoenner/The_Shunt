package defense

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Manager implements Engine.
type Manager struct {
	log   *slog.Logger
	ring  *Ring
	therm *Thermo
	bans  *Bans
	rep   *Reputation
	det   *Detector
	never *NeverSet
	dec   *Decoys
	rpts  *Reports
	dns   dnsState
	conn  connState
	now   func() time.Time

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

	onEvent func(Event, Class) // evidence log hook (WithEventHook)

	stop     context.CancelFunc
	done     chan struct{}
	closeOne sync.Once
}

// Option customises NewManager.
type Option func(*Manager)

// WithListen sets how decoy listeners are opened.
func WithListen(f ListenFunc) Option { return func(m *Manager) { m.dec.Listen = f } }

// WithBanHooks sets the callbacks for blocks and unblocks (firewall).
func WithBanHooks(onBan, onUnban func(Ban)) Option {
	return func(m *Manager) { m.bans.OnBan, m.bans.OnUnban = onBan, onUnban }
}

// WithSSHHostKey keeps the ssh decoy's host key in this file (created with
// mode 0600 on first use). Without it the key lives in memory only.
func WithSSHHostKey(path string) Option { return func(m *Manager) { m.dec.HostKeyPath = path } }

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
		rpts: NewReports(""), agg: map[aggKey]*aggEntry{}, rep: NewReputation(), never: &NeverSet{}, now: time.Now, class: ClassPublic, cfg: DefaultConfig()}
	m.cfg.Enabled = false
	m.det = NewDetector(DetectConfig{}, m.never)
	m.det.OnFound = m.found
	m.dec = NewDecoys(nil, m.decoyHit)
	m.dec.SSHDelay = sshDefaultDelay
	for _, o := range opts {
		o(m)
	}
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
			for _, b := range m.bans.Prune() {
				m.Report(Event{Kind: KindUnban, Severity: SevInfo, Src: b.Src, Detail: "expired"})
			}
			m.rep.Prune()
			m.flushAgg(false)
			if err := m.rpts.Flush(); err != nil {
				m.log.Debug("defense: report file", "err", err)
			}
			if err := m.flushFirstSeen(); err != nil {
				m.log.Debug("defense: first-contact file", "err", err)
			}
		}
	}
}

func (m *Manager) feature(name string) Feature {
	m.mu.Lock()
	defer m.mu.Unlock()
	return featureOf(m.cfg, name)
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
	m.mu.Lock()
	m.cfg = cfg
	m.never.SetConfig(ParsePrefixes(cfg.Never))
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
	}
	if changed && enabled {
		m.Report(Event{Kind: KindNetEnter, Severity: SevInfo, Detail: "class=" + string(class)})
	}
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
	if m.feature(FeatScan).Watch || m.feature(FeatBrute).Watch {
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
	if h.JA3 != "" {
		m.ja3Seen(h)
		return
	}
	m.Report(Event{Kind: h.Kind, Severity: h.Sev, Src: h.Src.String(), Port: h.Port, Proto: "tcp", Detail: h.Detail})
	if h.Kind == KindDecoyHit {
		m.Observe(h.Src, h.Port, "tcp", false)
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
	sev, feat := SevHigh, FeatScan
	if f.Kind == KindBruteForce {
		sev, feat = SevMedium, FeatBrute
	}
	m.Report(Event{Kind: f.Kind, Severity: sev, Src: f.Src.String(), Detail: f.Detail})
	m.maybeBan(f.Src, f.Kind, feat)
}

// maybeBan blocks src if the feature's Block switch is on and src is not on
// the never-list.
func (m *Manager) maybeBan(src netip.Addr, reason Kind, feat string) {
	m.mu.Lock()
	f := featureOf(m.cfg, feat)
	secs := m.cfg.BanSeconds
	m.mu.Unlock()
	src = src.Unmap()
	if !f.Watch || !f.Block || !src.IsValid() || m.never.Contains(src) {
		return
	}
	m.addBan(src, reason, time.Duration(secs)*time.Second)
}

// addBan blocks src, or its whole range while exposed (see banTarget).
func (m *Manager) addBan(src netip.Addr, reason Kind, d time.Duration) {
	target := m.banTarget(src)
	if target == "" {
		return
	}
	if p, err := netip.ParsePrefix(target); err == nil {
		for _, s := range m.bans.InRange(p) { // the range replaces its single entries
			m.bans.Remove(s)
		}
	}
	if b, isNew := m.bans.Add(target, reason, d); isNew {
		m.Report(Event{Kind: KindBan, Severity: SevLow, Src: b.Src, Detail: "reason=" + string(reason)})
	}
}

// ErrNeverBan is returned when a manual block hits the never-list.
var ErrNeverBan = errors.New("address is on the never-block list (gateway, DNS, portal or your own list)")

// Ban blocks src by hand for the configured time.
func (m *Manager) Ban(src string) error {
	a, err := netip.ParseAddr(strings.TrimSpace(src))
	if err != nil {
		return err
	}
	a = a.Unmap()
	m.mu.Lock()
	enabled, secs := m.cfg.Enabled, m.cfg.BanSeconds
	m.mu.Unlock()
	if !enabled {
		return errors.New("defense is off")
	}
	if m.never.Contains(a) {
		return ErrNeverBan
	}
	m.addBan(a, KindManual, time.Duration(secs)*time.Second)
	return nil
}

// Unban lifts one block ("" = all).
func (m *Manager) Unban(src string) {
	for _, b := range m.bans.Remove(src) {
		m.Report(Event{Kind: KindUnban, Severity: SevInfo, Src: b.Src, Detail: "manual"})
	}
}

// Events returns events with Seq > since.
func (m *Manager) Events(since uint64) EventsResponse { return m.ring.Events(since) }

// EventsFor returns the events of one source address (all kinds), oldest
// first. src is normalised (IPv4-mapped form, case); anything that is no
// address matches nothing.
func (m *Manager) EventsFor(src string) EventsResponse {
	a, err := netip.ParseAddr(src)
	if err != nil {
		return EventsResponse{Events: []Event{}, LastSeq: m.ring.LastSeq()}
	}
	return m.ring.EventsFor(a.Unmap().String())
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
