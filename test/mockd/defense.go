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
		Decoys: decoys, Bans: append([]defense.Ban{}, m.bans...), Counts: counts, LastSeq: m.seq, Config: m.cfg}
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
