package main

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"sync"
)

// A fake evidence log for the Defense tab. Documentation addresses only.

type mockEvidence struct {
	mu    sync.Mutex
	cases []map[string]any
}

var evd = &mockEvidence{}

func (m *mockDefense) handleEvidence(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/defense/evidence", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		ev := m.cfg.Evidence
		m.mu.Unlock()
		evd.mu.Lock()
		cases := append([]map[string]any{}, evd.cases...)
		evd.mu.Unlock()
		days := ev.RetentionDays
		if days == 0 {
			days = 90
		}
		js(w, map[string]any{
			"enabled": ev.Enabled, "capture": ev.Enabled && ev.Capture, "capture_supported": true,
			"config": map[string]any{"enabled": ev.Enabled, "retention_days": days},
			"status": map[string]any{"open": ev.Enabled, "files": 3, "lines": 412, "bytes": 183500, "chain_ok": true, "head_seq": 412, "pcap_bytes": 2400000},
			"cases":  cases,
		})
	})
	mux.HandleFunc("POST /v1/defense/evidence/case", func(w http.ResponseWriter, r *http.Request) {
		var q struct{ Action, ID, Name, Src string }
		_ = json.NewDecoder(r.Body).Decode(&q)
		evd.mu.Lock()
		defer evd.mu.Unlock()
		switch q.Action {
		case "create":
			if _, err := netip.ParseAddr(q.Src); err != nil {
				http.Error(w, `{"error":"src: not an IP address"}`, http.StatusBadRequest)
				return
			}
			c := map[string]any{"id": "c0ffee" + string(rune('0'+len(evd.cases))), "name": q.Name, "src": q.Src, "from_seq": 1, "to_seq": 0, "pinned": true}
			evd.cases = append(evd.cases, c)
			js(w, c)
			return
		case "pin", "unpin", "delete":
			keep := evd.cases[:0]
			for _, c := range evd.cases {
				if c["id"] == q.ID {
					if q.Action == "delete" {
						continue
					}
					c["pinned"] = q.Action == "pin"
				}
				keep = append(keep, c)
			}
			evd.cases = keep
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /v1/defense/evidence/purge", func(w http.ResponseWriter, r *http.Request) { js(w, map[string]int{"removed_files": 1}) })
	mux.HandleFunc("GET /v1/defense/evidence/networks", func(w http.ResponseWriter, r *http.Request) {
		js(w, map[string]any{"networks": []map[string]any{
			{"id": "a1b2c3d4", "class": "public", "visits": 2, "first_utc": "2026-11-10T08:00:00Z", "last_utc": "2026-11-11T09:00:00Z", "lines": 7, "sources": 2},
			{"id": "e5f6a7b8", "class": "trusted", "visits": 1, "first_utc": "2026-11-09T18:00:00Z", "last_utc": "2026-11-09T20:00:00Z", "lines": 1, "sources": 1}}})
	})
	mux.HandleFunc("POST /v1/defense/evidence/export", func(w http.ResponseWriter, r *http.Request) {
		var q struct {
			Preview bool `json:"preview"`
		}
		_ = json.NewDecoder(r.Body).Decode(&q)
		if q.Preview {
			js(w, map[string]any{"lines": 7, "sources": 2, "packets": 12, "first_utc": "2026-11-10T08:00:00Z", "last_utc": "2026-11-11T09:00:00Z",
				"kinds": []string{"decoy_hit", "scan"}, "chain_only": 3, "files": []string{"events.jsonl", "chain.jsonl", "manifest.json"}})
			return
		}
		js(w, map[string]any{"path": "/var/lib/shunt/defense/evidence/exports/shunt-case-demo.tar.gz", "bytes": 5, "lines": 7, "packets": 12, "addresses": 1})
	})
	mux.HandleFunc("GET /v1/defense/evidence/download", func(w http.ResponseWriter, r *http.Request) {
		js(w, map[string]any{"name": r.URL.Query().Get("name"), "size": 5, "data": []byte("demo!")})
	})
	mux.HandleFunc("GET /v1/defense/evidence/abuse", func(w http.ResponseWriter, r *http.Request) {
		js(w, map[string]any{"ip": r.URL.Query().Get("src"), "operator": "EXAMPLE-NET (Example Org)", "country": "ZZ", "network": "192.0.2.0/24",
			"abuse_email": "abuse@example.net", "registry": "rdap.example.net"})
	})
}
