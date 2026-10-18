package blocklist

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
)

// Download limits and timing.
const (
	MaxSize    = 64 << 20 // per list
	RefreshAge = 24 * time.Hour
	RetryAfter = 10 * time.Minute
)

// Status describes one list for the UI.
type Status struct {
	Name    string    `json:"name"`
	URL     string    `json:"url"`
	Levels  []string  `json:"levels"`
	Entries int       `json:"entries"`
	Updated time.Time `json:"updated,omitzero"`
	Error   string    `json:"error,omitempty"`
}

type entry struct {
	ref, url string
	allow    bool // an allowlist
	list     *List
	updated  time.Time // of the cached file
	tried    time.Time // last download attempt
	err      string
	loading  bool // reading the cache, not due yet
}

// Manager keeps the lists of the levels in use loaded and fresh. Lists of
// levels nobody uses are neither downloaded nor kept in memory.
type Manager struct {
	Dir string
	Log *slog.Logger
	// Client returns the HTTP client for downloads (it follows the
	// default route, so it may change with every reload).
	Client func() *http.Client
	// OnChange receives every new filter snapshot.
	OnChange func(*Filter)

	mu      sync.Mutex
	cfg     config.DNSFilter
	used    []string
	entries map[string]*entry
	kick    chan struct{}
	now     func() time.Time
}

// Configure sets the filter config and the levels in use. Lists that are
// no longer needed are dropped; new ones are loaded from the cache and
// downloaded in the background (Run).
func (m *Manager) Configure(cfg config.DNSFilter, used []string) {
	m.mu.Lock()
	if m.entries == nil {
		m.entries = map[string]*entry{}
		m.kick = make(chan struct{}, 1)
	}
	m.cfg, m.used = cfg, used
	want := map[string]bool{}
	for _, lvl := range used {
		for _, ref := range cfg.Lists(lvl) {
			want[ref] = false
		}
	}
	if len(used) > 0 { // allowlists only matter while something is filtered
		for _, ref := range cfg.AllowLists {
			if _, ok := want[ref]; !ok {
				want[ref] = true
			}
		}
	}
	for ref, e := range m.entries {
		if _, ok := want[ref]; !ok || e.url != cfg.ListURL(ref) || e.allow != want[ref] {
			delete(m.entries, ref)
		}
	}
	var load []*entry
	for ref, allow := range want {
		if m.entries[ref] == nil {
			e := &entry{ref: ref, url: cfg.ListURL(ref), allow: allow, loading: true}
			m.entries[ref] = e
			load = append(load, e)
		}
	}
	kick := m.kick
	m.mu.Unlock()
	m.publish() // dropped lists and allowlist changes at once
	// Parsing a big list takes a moment: don't hold up the reload.
	go func() {
		for _, e := range load {
			m.loadCache(e)
		}
		if len(load) > 0 {
			m.publish()
		}
		select {
		case kick <- struct{}{}:
		default:
		}
	}()
}

// Run downloads missing and stale lists until ctx ends.
func (m *Manager) Run(ctx context.Context) {
	m.mu.Lock()
	if m.kick == nil {
		m.entries = map[string]*entry{}
		m.kick = make(chan struct{}, 1)
	}
	kick := m.kick
	m.mu.Unlock()
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		m.refresh(ctx)
		select {
		case <-ctx.Done():
			return
		case <-kick:
		case <-t.C:
		}
	}
}

// Refresh updates every list now (UI button).
func (m *Manager) Refresh() {
	m.mu.Lock()
	for _, e := range m.entries {
		e.updated, e.tried = time.Time{}, time.Time{}
	}
	kick := m.kick
	m.mu.Unlock()
	if kick != nil {
		select {
		case kick <- struct{}{}:
		default:
		}
	}
}

func (m *Manager) clock() time.Time {
	if m.now != nil {
		return m.now()
	}
	return time.Now()
}

func (m *Manager) refresh(ctx context.Context) {
	m.mu.Lock()
	var due []*entry
	now := m.clock()
	for _, e := range m.entries {
		if !e.loading && now.Sub(e.updated) >= RefreshAge && now.Sub(e.tried) >= RetryAfter {
			due = append(due, e)
		}
	}
	m.mu.Unlock()
	slices.SortFunc(due, func(a, b *entry) int { return strings.Compare(a.ref, b.ref) })
	changed := false
	for _, e := range due {
		if ctx.Err() != nil {
			return
		}
		l, mod, err := m.download(ctx, e)
		m.mu.Lock()
		e.tried = m.clock()
		if err != nil {
			e.err = err.Error()
			m.Log.Warn("dns filter: list download failed", "list", e.ref, "err", err)
		} else {
			e.err, e.updated = "", m.clock()
			if l != nil {
				e.list, changed = l, true
				m.Log.Info("dns filter: list updated", "list", e.ref, "entries", l.Len(), "modified", mod)
			}
		}
		m.mu.Unlock()
	}
	if changed {
		m.publish()
	}
}

var safeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func (m *Manager) file(e *entry) string {
	h := sha256.Sum256([]byte(e.url))
	base := filepath.Base(e.url)
	base = safeName.ReplaceAllString(base, "_")
	if len(base) > 60 {
		base = base[:60]
	}
	return filepath.Join(m.Dir, base+"-"+hex.EncodeToString(h[:6])+".txt")
}

func (m *Manager) loadCache(e *entry) {
	defer func() {
		m.mu.Lock()
		e.loading = false
		m.mu.Unlock()
	}()
	if config.IsLocalList(e.url) { // no cache: the file itself, read again on every refresh
		m.loadLocal(e)
		return
	}
	f, err := os.Open(m.file(e))
	if err != nil {
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return
	}
	l, err := m.parse(e, io.LimitReader(f, MaxSize))
	if err != nil {
		m.Log.Warn("dns filter: cached list unusable", "list", e.ref, "err", err)
		return
	}
	m.mu.Lock()
	e.list, e.updated = l, st.ModTime()
	m.mu.Unlock()
}

// localInfo opens a local list: a regular file only.
func localOpen(e *entry) (*os.File, os.FileInfo, error) {
	f, err := os.Open(config.LocalListPath(e.url))
	if err != nil {
		return nil, nil, err
	}
	st, err := f.Stat()
	if err == nil && !st.Mode().IsRegular() {
		err = fmt.Errorf("%s is not a regular file", e.url)
	}
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, st, nil
}

func (m *Manager) loadLocal(e *entry) {
	f, st, err := localOpen(e)
	if err == nil {
		defer f.Close()
		var l *List
		if l, err = m.parse(e, io.LimitReader(f, MaxSize)); err == nil {
			m.mu.Lock()
			e.list, e.updated, e.err = l, m.clock(), ""
			m.mu.Unlock()
			m.Log.Info("dns filter: local list read", "list", e.ref, "entries", l.Len(), "modified", st.ModTime())
			return
		}
	}
	m.mu.Lock()
	e.err = err.Error()
	m.mu.Unlock()
	m.Log.Warn("dns filter: local list unusable", "list", e.ref, "err", err)
}

// download fetches e. A nil list without error: not modified.
func (m *Manager) download(ctx context.Context, e *entry) (*List, string, error) {
	if config.IsLocalList(e.url) {
		f, st, err := localOpen(e)
		if err != nil {
			return nil, "", err
		}
		defer f.Close()
		l, err := m.parse(e, io.LimitReader(f, MaxSize))
		return l, st.ModTime().Format(http.TimeFormat), err
	}
	path := m.file(e)
	req, err := http.NewRequestWithContext(ctx, "GET", e.url, nil)
	if err != nil {
		return nil, "", err
	}
	m.mu.Lock()
	have := e.list != nil
	m.mu.Unlock()
	if st, err := os.Stat(path); err == nil && have {
		req.Header.Set("If-Modified-Since", st.ModTime().UTC().Format(http.TimeFormat))
	}
	cl := http.DefaultClient
	if m.Client != nil {
		cl = m.Client()
	}
	resp, err := cl.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		now := m.clock()
		_ = os.Chtimes(path, now, now)
		return nil, "", nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("%s: %s", e.url, resp.Status)
	}
	if err := os.MkdirAll(m.Dir, 0o755); err != nil {
		return nil, "", err
	}
	tmp, err := os.CreateTemp(m.Dir, ".dl-*")
	if err != nil {
		return nil, "", err
	}
	defer os.Remove(tmp.Name())
	n, err := io.Copy(tmp, io.LimitReader(resp.Body, MaxSize+1))
	if err == nil && n > MaxSize {
		err = fmt.Errorf("larger than %d MiB", MaxSize>>20)
	}
	if err == nil {
		_, err = tmp.Seek(0, io.SeekStart)
	}
	var l *List
	if err == nil {
		l, err = m.parse(e, tmp)
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, "", err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return nil, "", err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return nil, "", err
	}
	return l, resp.Header.Get("Last-Modified"), nil
}

func (m *Manager) parse(e *entry, r io.Reader) (*List, error) {
	if e.allow {
		return ParseAllow(e.ref, r)
	}
	return Parse(e.ref, r)
}

func (m *Manager) publish() {
	m.mu.Lock()
	levels := map[string][]*List{}
	for _, lvl := range m.used {
		for _, ref := range m.cfg.Lists(lvl) {
			if e := m.entries[ref]; e != nil && e.list != nil {
				levels[lvl] = append(levels[lvl], e.list)
			}
		}
	}
	var allow []string
	for _, a := range m.cfg.Allow {
		if d := config.NormalizeDomain(a); d != "" {
			allow = append(allow, d)
		}
	}
	var allowLists []*List
	for _, ref := range m.cfg.AllowLists {
		if e := m.entries[ref]; e != nil && e.allow && e.list != nil {
			allowLists = append(allowLists, e.list)
		}
	}
	f := NewFilter(levels, allow)
	f.allowLists = allowLists
	m.mu.Unlock()
	if m.OnChange != nil {
		m.OnChange(f)
	}
}

// Status lists the lists in use.
func (m *Manager) Status() []Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Status
	for ref, e := range m.entries {
		s := Status{Name: ref, URL: e.url, Updated: e.updated, Error: e.err}
		if e.list != nil {
			s.Entries = e.list.Len()
		}
		for _, lvl := range m.used {
			if slices.Contains(m.cfg.Lists(lvl), ref) {
				s.Levels = append(s.Levels, lvl)
			}
		}
		if e.allow {
			s.Levels = append(s.Levels, "allow")
		}
		out = append(out, s)
	}
	slices.SortFunc(out, func(a, b Status) int { return strings.Compare(a.Name, b.Name) })
	return out
}
