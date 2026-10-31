package speedtest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// HistoryKeep is how many finished tests the history keeps (one test = one
// run over several routes).
const HistoryKeep = 3

// HistRoute is one route's median in a stored test. No addresses, host or
// network names (SSIDs) are stored, only route names.
type HistRoute struct {
	Route     string  `json:"route"`
	State     string  `json:"state"`
	LatencyMs float64 `json:"latency_ms,omitempty"`
	DownMbit  float64 `json:"down_mbit,omitempty"`
	UpMbit    float64 `json:"up_mbit,omitempty"`
}

// HistEntry is one finished test.
type HistEntry struct {
	Time     time.Time   `json:"time"`
	Network  string      `json:"network,omitempty"` // [[network]] profile name
	Provider string      `json:"provider"`
	Rounds   int         `json:"rounds"`
	Seed     uint64      `json:"seed"`
	Routes   []HistRoute `json:"routes"`
}

// HistoryPath is the file of the history of the current user ("" if the
// user has no config directory).
func HistoryPath() string {
	d, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(d, "shunt", "speedtest-history.json")
}

var histMu sync.Mutex

// LoadHistory reads the history, newest first. A missing or broken file
// gives an empty list.
func LoadHistory(path string) []HistEntry {
	if path == "" {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var h []HistEntry
	if json.Unmarshal(b, &h) != nil {
		return nil
	}
	if len(h) > HistoryKeep {
		h = h[:HistoryKeep]
	}
	return h
}

// Entry makes the history entry of a report.
func Entry(rep *Report, network string) HistEntry {
	e := HistEntry{Time: rep.Started, Network: network, Provider: rep.Provider, Rounds: rep.Rounds, Seed: rep.Seed}
	for _, r := range rep.Routes {
		e.Routes = append(e.Routes, HistRoute{Route: r.Route, State: r.State, LatencyMs: r.LatencyMs, DownMbit: r.DownMbit, UpMbit: r.UpMbit})
	}
	return e
}

// HistoryOff reports whether the user switched the history off (View →
// Opsec, "keep no speed test history"): the key "shunt-no-history" in the
// ui-state file next to the history file (internal/ui keeps it there).
func HistoryOff(path string) bool {
	if path == "" {
		return false
	}
	b, err := os.ReadFile(filepath.Join(filepath.Dir(path), "ui-state.json"))
	if err != nil {
		return false
	}
	var st map[string]string
	return json.Unmarshal(b, &st) == nil && st["shunt-no-history"] == "1"
}

// ClearHistory removes the history file (a missing one is fine).
func ClearHistory(path string) error {
	if path == "" {
		return nil
	}
	histMu.Lock()
	defer histMu.Unlock()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// AddHistory puts the report in front of the history and keeps the last
// HistoryKeep tests. The file is written whole to a temporary name and
// renamed (mode 0600). Nothing is stored while the history is off.
func AddHistory(path string, rep *Report, network string) error {
	if path == "" || rep == nil || len(rep.Routes) == 0 || HistoryOff(path) {
		return nil
	}
	histMu.Lock()
	defer histMu.Unlock()
	h := append([]HistEntry{Entry(rep, network)}, LoadHistory(path)...)
	if len(h) > HistoryKeep {
		h = h[:HistoryKeep]
	}
	b, err := json.MarshalIndent(h, "", " ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".speedtest-history-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
