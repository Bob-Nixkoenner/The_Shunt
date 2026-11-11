package defense

import (
	"context"
	"log/slog"
	"net/netip"
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
	now   func() time.Time

	syncMu sync.Mutex // serialises decoy start/stop; never taken with mu held
	mu     sync.Mutex
	cfg    Config
	key    string
	class  Class

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
		rep: NewReputation(), never: &NeverSet{}, now: time.Now, class: ClassPublic, cfg: DefaultConfig()}
	m.cfg.Enabled = false
	m.det = NewDetector(DetectConfig{}, m.never)
	m.det.OnFound = m.found
	m.dec = NewDecoys(nil, m.decoyHit)
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
	m.mu.Unlock()
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
	m.mu.Unlock()
	m.syncDecoys()
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
	cfg, class := m.cfg, m.class
	m.mu.Unlock()
	if f := featureOf(cfg, FeatDecoy); !f.Watch || !class.Decoys() {
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
	ev = m.ring.Add(ev)
	m.therm.Add(ev)
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
	m.maybeBan(a, KindReputation, FeatReputation)
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
			m.maybeBan(h.Src, KindReputation, FeatReputation)
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
	if b, isNew := m.bans.Add(src.String(), reason, time.Duration(secs)*time.Second); isNew {
		m.Report(Event{Kind: KindBan, Severity: SevLow, Src: b.Src, Detail: "reason=" + string(reason)})
	}
}

// Unban lifts one block ("" = all).
func (m *Manager) Unban(src string) {
	for _, b := range m.bans.Remove(src) {
		m.Report(Event{Kind: KindUnban, Severity: SevInfo, Src: b.Src, Detail: "manual"})
	}
}

// Events returns events with Seq > since.
func (m *Manager) Events(since uint64) EventsResponse { return m.ring.Events(since) }

// Status returns the current state.
func (m *Manager) Status() Status {
	m.mu.Lock()
	cfg, class := m.cfg, m.class
	m.mu.Unlock()
	heat := m.therm.Heat()
	return Status{Enabled: cfg.Enabled, Class: class, Heat: heat, Level: LevelFor(heat),
		Decoys: m.dec.Ports(), Bans: m.bans.List(), Counts: m.therm.Counts(),
		LastSeq: m.ring.LastSeq(), Config: cfg}
}

// Close stops everything. It is safe to call twice.
func (m *Manager) Close() {
	m.closeOne.Do(func() {
		m.stop()
		<-m.done
		m.dec.Stop()
	})
}

var _ Engine = (*Manager)(nil)

// Watching reports whether feature name is switched on for detection (and
// the defense as a whole is enabled).
func (m *Manager) Watching(name string) bool { return m.feature(name).Watch }
