package main

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/api"
	"github.com/Bob-Nixkoenner/the_shunt/internal/defense"
)

// A fake defense: the heat swings through all four levels in a cycle (or
// stays where -heat puts it), events appear while it is warm and bans
// follow the worst ones. All addresses are documentation ranges.

var fixedHeat = -1 // -heat: >= 0 pins the gauge

type mockDefense struct {
	mu     sync.Mutex
	start  time.Time
	last   time.Time
	events []defense.Event
	bans   []defense.Ban
	cfg    defense.Config
	seq    uint64
	rng    uint32
}

var dfn = newMockDefense()

func newMockDefense() *mockDefense {
	cfg := defense.DefaultConfig()
	cfg.Enabled = true
	cfg.Features[defense.FeatDecoy] = defense.Feature{Watch: true}
	m := &mockDefense{start: time.Now(), last: time.Now(), cfg: cfg}
	m.rng = 12345
	// some history so the page is not empty at the start
	for i := 0; i < 6; i++ {
		m.add(time.Now().Add(-time.Duration(90-i*12)*time.Second), m.pick())
	}
	return m
}

func (m *mockDefense) rand(n int) int {
	m.rng = m.rng*1664525 + 1013904223
	return int(m.rng>>8) % n
}

var kindFeature = map[defense.Kind]string{
	defense.KindCowrie: defense.FeatCowrie, defense.KindScan: defense.FeatScan, defense.KindBruteForce: defense.FeatBrute,
	defense.KindTarpit: defense.FeatTarpit, defense.KindDecoyHit: defense.FeatDecoy,
}

var mockSrc = []string{"192.0.2.17", "192.0.2.44", "198.51.100.23", "198.51.100.150", "203.0.113.8", "203.0.113.99"}

func (m *mockDefense) pick() defense.Event {
	src := mockSrc[m.rand(len(mockSrc))]
	switch m.rand(8) {
	case 0:
		return defense.Event{Kind: defense.KindTarpit, Severity: defense.SevMedium, Src: src, Port: 22, Proto: "tcp", Detail: "held in the tarpit"}
	case 1:
		return defense.Event{Kind: defense.KindCowrie, Severity: defense.SevHigh, Src: src, Port: 23, Proto: "tcp", Detail: "login attempt: admin / admin"}
	case 2:
		return defense.Event{Kind: defense.KindScan, Severity: defense.SevMedium, Src: src, Proto: "tcp", Detail: "41 ports in 3 s"}
	case 3:
		return defense.Event{Kind: defense.KindARP, Severity: defense.SevHigh, Src: "192.0.2.1", Detail: "gateway address changed hands"}
	case 4:
		return defense.Event{Kind: defense.KindDNSHijack, Severity: defense.SevHigh, Detail: "answers differ from the encrypted resolver"}
	case 5:
		return defense.Event{Kind: defense.KindDecoyHit, Severity: defense.SevLow, Src: src, Port: 445, Proto: "tcp", Detail: "connection to a decoy port"}
	case 6:
		return defense.Event{Kind: defense.KindObservation, Severity: defense.SevInfo, Detail: "broadcast chatter from a neighbour"}
	}
	return defense.Event{Kind: defense.KindBruteForce, Severity: defense.SevMedium, Src: src, Port: 22, Proto: "tcp", Detail: "37 failed connections in a minute"}
}

func (m *mockDefense) add(t time.Time, ev defense.Event) {
	m.seq++
	ev.Seq, ev.Time = m.seq, t
	m.events = append(m.events, ev)
	if len(m.events) > 400 {
		m.events = m.events[len(m.events)-400:]
	}
	if ev.Severity == defense.SevHigh && ev.Src != "" && ev.Src != "192.0.2.1" && m.cfg.Features[kindFeature[ev.Kind]].Block {
		m.ban(ev.Src, ev.Kind, t)
	}
}

func (m *mockDefense) ban(src string, why defense.Kind, t time.Time) {
	for _, b := range m.bans {
		if b.Src == src {
			return
		}
	}
	m.bans = append(m.bans, defense.Ban{Src: src, Reason: why, Since: t, Expires: t.Add(time.Duration(m.cfg.BanSeconds) * time.Second)})
}

// heat: 0 -> 100 -> 0 over 150 s: quiet, noticed, hot, attack, cooling
func (m *mockDefense) heat(now time.Time) int {
	if fixedHeat >= 0 {
		return fixedHeat
	}
	ph := math.Mod(now.Sub(m.start).Seconds(), 150) / 150
	return int(math.Round(100 * math.Pow(math.Sin(math.Pi*ph), 2) * 1.0))
}

// advance makes the events of the time since the last call
func (m *mockDefense) advance(now time.Time) {
	for t := m.last; t.Before(now); t = t.Add(2 * time.Second) {
		h := m.heat(t)
		if h >= 25 && m.rand(100) < h {
			m.add(t, m.pick())
		}
		if h >= 80 && m.rand(100) < 30 {
			m.add(t, defense.Event{Kind: defense.KindCowrie, Severity: defense.SevHigh, Src: mockSrc[m.rand(len(mockSrc))], Port: 23, Proto: "tcp", Detail: "login attempt: root / 123456"})
		}
	}
	m.last = now
	live := m.bans[:0]
	for _, b := range m.bans {
		if b.Expires.After(now) {
			live = append(live, b)
		}
	}
	m.bans = live
}

func (m *mockDefense) status() defense.Status {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.advance(now)
	h := m.heat(now)
	counts := map[defense.Kind]int{}
	for _, e := range m.events {
		counts[e.Kind]++
	}
	decoys := []int{}
	if m.cfg.Enabled && defense.ClassPublic.Decoys() {
		decoys = m.cfg.DecoyPorts
	}
	return defense.Status{Enabled: m.cfg.Enabled, Class: defense.ClassPublic, Heat: h, Level: defense.LevelFor(h),
		Decoys: decoys, Bans: append([]defense.Ban{}, m.bans...), Counts: counts, LastSeq: m.seq, Config: m.cfg, Sources: m.sources()}
}

func (m *mockDefense) brief() *api.DefenseBrief {
	st := m.status()
	if !st.Enabled {
		return nil
	}
	return &api.DefenseBrief{Heat: st.Heat, Level: st.Level, Class: st.Class}
}

func (m *mockDefense) handle(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/defense", func(w http.ResponseWriter, r *http.Request) { js(w, m.status()) })
	mux.HandleFunc("GET /v1/defense/events", func(w http.ResponseWriter, r *http.Request) {
		since, _ := strconv.ParseUint(r.URL.Query().Get("since"), 10, 64)
		m.mu.Lock()
		defer m.mu.Unlock()
		m.advance(time.Now())
		if src := r.URL.Query().Get("src"); src != "" {
			out := []defense.Event{}
			for _, e := range m.events {
				if e.Src == src {
					out = append(out, e)
				}
			}
			js(w, defense.EventsResponse{Events: out, LastSeq: m.seq})
			return
		}
		out := []defense.Event{}
		for _, e := range m.events {
			if e.Seq > since && len(out) < 200 {
				out = append(out, e)
			}
		}
		js(w, defense.EventsResponse{Events: out, LastSeq: m.seq})
	})
	mux.HandleFunc("POST /v1/defense/config", func(w http.ResponseWriter, r *http.Request) {
		var c defense.Config
		if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
			return
		}
		m.mu.Lock()
		m.cfg = c
		m.mu.Unlock()
		js(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("GET /v1/defense/reports", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.advance(time.Now())
		export := r.URL.Query().Get("export") == "1"
		cur := defense.NetReport{Key: "9f3c1a07d2e45b68", Class: defense.ClassPublic, Counts: map[defense.Kind]int{},
			FirstSeen: m.start, LastSeen: time.Now(), PeakHeat: m.heat(time.Now()), DNSRedirect: defense.PropNoneSeen,
			Captive: defense.PropYes, Isolation: defense.PropUnknown, Sources: map[string]int{}}
		for _, e := range m.events {
			cur.Counts[e.Kind]++
			if c := defense.CutSource(e.Src); c != "" {
				cur.Sources[c]++
			}
		}
		old := defense.NetReport{Key: "41b8e6d0a97c3f25", Class: defense.ClassTrusted,
			Counts:    map[defense.Kind]int{defense.KindFirstSeen: 12, defense.KindObservation: 3},
			FirstSeen: m.start.Add(-72 * time.Hour), LastSeen: m.start.Add(-70 * time.Hour), PeakHeat: 18,
			DNSRedirect: defense.PropNoneSeen, Captive: defense.PropNoneSeen, Isolation: defense.PropUnknown,
			Sources: map[string]int{"198.51.100.0/24": 3}}
		hot := defense.NetReport{Key: "c07d55e19a3b8642", Class: defense.ClassPublic,
			Counts:    map[defense.Kind]int{defense.KindScan: 4, defense.KindDecoyHit: 31, defense.KindDNSHijack: 1, defense.KindCowrie: 6},
			FirstSeen: m.start.Add(-30 * time.Hour), LastSeen: m.start.Add(-28 * time.Hour), PeakHeat: 91,
			DNSRedirect: defense.PropYes, Captive: defense.PropUnknown, Isolation: defense.PropUnknown,
			Sources: map[string]int{"203.0.113.0/24": 38, "2001:db8:5::/48": 4}}
		rs := []defense.NetReport{cur, old, hot}
		curKey := cur.Key
		if export {
			for i := range rs {
				rs[i].Key = rs[i].Key[:8]
			}
			curKey = ""
		}
		js(w, defense.ReportsResponse{Reports: rs, Current: curKey, Export: export})
	})
	mux.HandleFunc("POST /v1/defense/ban", func(w http.ResponseWriter, r *http.Request) {
		var u api.DefenseUnban
		_ = json.NewDecoder(r.Body).Decode(&u)
		m.mu.Lock()
		now := time.Now()
		m.bans = append(m.bans, defense.Ban{Src: u.Src, Reason: defense.KindManual, Since: now, Expires: now.Add(time.Hour)})
		m.mu.Unlock()
		js(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /v1/defense/unban", func(w http.ResponseWriter, r *http.Request) {
		var u api.DefenseUnban
		_ = json.NewDecoder(r.Body).Decode(&u)
		m.mu.Lock()
		keep := []defense.Ban{}
		for _, b := range m.bans {
			if u.Src != "" && b.Src != u.Src {
				keep = append(keep, b)
			}
		}
		m.bans = keep
		m.mu.Unlock()
		js(w, map[string]bool{"ok": true})
	})
}

// sources fakes the list status from the switches (numbers are made up).
func (m *mockDefense) sources() []defense.SourceInfo {
	on := map[string]bool{}
	for _, s := range defense.SourcesFor(m.cfg.ReputationSources, m.cfg.ReputationOff) {
		on[s.Name] = true
	}
	ago := time.Now().Add(-3 * time.Hour)
	out := []defense.SourceInfo{
		{Name: "feodo", On: on["feodo"], Entries: 214, Updated: ago},
		{Name: "sslbl", On: on["sslbl"], Entries: 1043, Updated: ago},
		{Name: "sslbl_ja3", On: on["sslbl_ja3"], Entries: 87, Updated: ago},
		{Name: "et_compromised", On: on["et_compromised"], Error: "http 503"},
	}
	for i := range out {
		out[i].Quality = defense.QualityList(out[i].Name)
		if !out[i].On {
			out[i].Entries, out[i].Updated, out[i].Error = 0, time.Time{}, ""
		}
	}
	return append(out, defense.SourceInfo{Name: defense.SpamhausDROP, Unavailable: true})
}
