// Package stats keeps traffic totals per tunnel and month - only sums, no
// connection records. Fed with the tunnel's byte counters (which start at
// zero again whenever the tunnel is re-created), it adds up the growth and
// stores it in a small JSON file. Same code on every platform.
package stats

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Bytes is received and sent traffic.
type Bytes struct {
	RX int64 `json:"rx"`
	TX int64 `json:"tx"`
}

func (b *Bytes) add(o Bytes) { b.RX += o.RX; b.TX += o.TX }

// Summary is what UIs show for one tunnel (or "total" for all of them).
type Summary struct {
	Month     Bytes `json:"month"`      // this calendar month
	LastMonth Bytes `json:"last_month"` // the one before
	Total     Bytes `json:"total"`      // since counting began
	Since     int64 `json:"since"`      // unix seconds, first count
}

type file struct {
	Version int                         `json:"version"`
	Since   map[string]int64            `json:"since"`  // tunnel -> unix
	Months  map[string]map[string]Bytes `json:"months"` // tunnel -> "2026-10" -> bytes
}

// Book is the counter store. Safe for concurrent use.
type Book struct {
	mu    sync.Mutex
	path  string // "" = memory only
	f     file
	last  map[string]Bytes // last counter values seen per tunnel
	dirty bool
	saved time.Time
}

// SaveEvery: at most this often to disk (flash wear on phones); Close saves.
const SaveEvery = 5 * time.Minute

// Open loads path (a missing file is fine; "" keeps everything in memory).
func Open(path string) (*Book, error) {
	b := &Book{path: path, last: map[string]Bytes{}, f: file{Version: 1, Since: map[string]int64{}, Months: map[string]map[string]Bytes{}}}
	if path == "" {
		return b, nil
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return b, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &b.f); err != nil {
		// a broken file must not stop the VPN: start over, keep the old one
		os.Rename(path, path+".broken")
		b.f = file{Version: 1, Since: map[string]int64{}, Months: map[string]map[string]Bytes{}}
	}
	if b.f.Since == nil {
		b.f.Since = map[string]int64{}
	}
	if b.f.Months == nil {
		b.f.Months = map[string]map[string]Bytes{}
	}
	return b, nil
}

func month(t time.Time) string { return t.Format("2006-01") }

// Observe feeds the current counters of a tunnel. The first value after
// Open (or after the tunnel was re-created) is only a starting point;
// counters that went down mean a new tunnel, whose bytes all count.
func (b *Book) Observe(tunnel string, rx, tx int64, now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	cur := Bytes{rx, tx}
	prev, seen := b.last[tunnel]
	b.last[tunnel] = cur
	if !seen {
		return
	}
	d := Bytes{rx - prev.RX, tx - prev.TX}
	if d.RX < 0 || d.TX < 0 { // re-created tunnel: counters restarted
		d = cur
	}
	if d.RX == 0 && d.TX == 0 {
		return
	}
	if _, ok := b.f.Since[tunnel]; !ok {
		b.f.Since[tunnel] = now.Unix()
	}
	m := b.f.Months[tunnel]
	if m == nil {
		m = map[string]Bytes{}
		b.f.Months[tunnel] = m
	}
	v := m[month(now)]
	v.add(d)
	m[month(now)] = v
	b.dirty = true
	if b.path != "" && now.Sub(b.saved) >= SaveEvery {
		b.saveLocked(now)
	}
}

// Forget drops the counter memory of a tunnel that went away (its next
// values start fresh); the totals stay.
func (b *Book) Forget(tunnel string) {
	b.mu.Lock()
	delete(b.last, tunnel)
	b.mu.Unlock()
}

// Summaries per tunnel, plus "total" over all tunnels.
func (b *Book) Summaries(now time.Time) map[string]Summary {
	b.mu.Lock()
	defer b.mu.Unlock()
	this, prev := month(now), month(time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location()).AddDate(0, -1, 0))
	out := map[string]Summary{}
	var all Summary
	for tunnel, months := range b.f.Months {
		s := Summary{Since: b.f.Since[tunnel]}
		for m, v := range months {
			s.Total.add(v)
			switch m {
			case this:
				s.Month.add(v)
			case prev:
				s.LastMonth.add(v)
			}
		}
		out[tunnel] = s
		all.Month.add(s.Month)
		all.LastMonth.add(s.LastMonth)
		all.Total.add(s.Total)
		if all.Since == 0 || (s.Since != 0 && s.Since < all.Since) {
			all.Since = s.Since
		}
	}
	out["total"] = all
	return out
}

// Months returns one tunnel's history, oldest first ("2026-10", bytes).
func (b *Book) Months(tunnel string) []struct {
	Month string
	Bytes
} {
	b.mu.Lock()
	defer b.mu.Unlock()
	var ms []string
	for m := range b.f.Months[tunnel] {
		ms = append(ms, m)
	}
	sort.Strings(ms)
	out := make([]struct {
		Month string
		Bytes
	}, len(ms))
	for i, m := range ms {
		out[i].Month, out[i].Bytes = m, b.f.Months[tunnel][m]
	}
	return out
}

// Reset deletes all counts (the user asked for it).
func (b *Book) Reset() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.f.Since, b.f.Months = map[string]int64{}, map[string]map[string]Bytes{}
	b.dirty = true
	return b.saveLocked(time.Now())
}

// Close writes pending counts.
func (b *Book) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.saveLocked(time.Now())
}

func (b *Book) saveLocked(now time.Time) error {
	if b.path == "" || !b.dirty {
		return nil
	}
	raw, err := json.Marshal(b.f)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(b.path), 0o700); err != nil {
		return err
	}
	tmp := b.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, b.path); err != nil {
		return err
	}
	b.dirty, b.saved = false, now
	return nil
}
