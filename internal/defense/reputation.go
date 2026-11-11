package defense

import (
	"bufio"
	"context"
	_ "embed"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Lists with CC0 licence (abuse.ch terms of use, section 3.4, checked
// 2026-11-11). Spamhaus lists are deliberately not used.
const (
	FeodoURL = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
	SSLBLURL = "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt"
)

//go:embed testdata/example_list.txt
var exampleList string

// ExampleList is a tiny built-in list (documentation ranges only).
func ExampleList() string { return exampleList }

// ParseList reads one address or CIDR per line. '#' starts a comment, and
// only the first field (split at comma, semicolon or space) is used, so CSV
// lists work too. Invalid lines are skipped.
func ParseList(r io.Reader) []netip.Prefix {
	var out []netip.Prefix
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		line, _, _ := strings.Cut(sc.Text(), "#")
		line = strings.TrimSpace(line)
		if i := strings.IndexAny(line, ", ;\t"); i >= 0 {
			line = line[:i]
		}
		line = strings.Trim(line, `"`)
		if line == "" {
			continue
		}
		if p, ok := parsePrefix(line); ok {
			out = append(out, p)
		}
	}
	return out
}

type repList struct {
	prefixes map[netip.Prefix]struct{}
	bits     map[int]bool // prefix lengths present
	expires  time.Time    // zero = never
}

// Reputation is a set of named bad-address lists with expiry.
type Reputation struct {
	mu    sync.RWMutex
	lists map[string]*repList
	now   func() time.Time
}

// NewReputation returns an empty set.
func NewReputation() *Reputation {
	return &Reputation{lists: map[string]*repList{}, now: time.Now}
}

// SetList replaces list name. A zero expires means it never expires.
func (r *Reputation) SetList(name string, p []netip.Prefix, expires time.Time) {
	l := &repList{prefixes: make(map[netip.Prefix]struct{}, len(p)), bits: map[int]bool{}, expires: expires}
	for _, x := range p {
		x = x.Masked()
		l.prefixes[x] = struct{}{}
		l.bits[x.Bits()] = true
	}
	r.mu.Lock()
	r.lists[name] = l
	r.mu.Unlock()
}

// Lookup returns the name of a list that contains a (and has not expired).
func (r *Reputation) Lookup(a netip.Addr) (string, bool) {
	a = a.Unmap()
	if !a.IsValid() {
		return "", false
	}
	now := r.now()
	r.mu.RLock()
	defer r.mu.RUnlock()
	for name, l := range r.lists {
		if !l.expires.IsZero() && !now.Before(l.expires) {
			continue
		}
		for b := range l.bits {
			if b > a.BitLen() {
				continue
			}
			if _, ok := l.prefixes[netip.PrefixFrom(a, b).Masked()]; ok {
				return name, true
			}
		}
	}
	return "", false
}

// Prune drops expired lists.
func (r *Reputation) Prune() {
	now := r.now()
	r.mu.Lock()
	for n, l := range r.lists {
		if !l.expires.IsZero() && !now.Before(l.expires) {
			delete(r.lists, n)
		}
	}
	r.mu.Unlock()
}

// Source is a downloadable list.
type Source struct {
	Name string
	URL  string
	TTL  time.Duration // how long its entries count after a download (default 24 h)
}

// DefaultSources are the two built-in CC0 lists.
var DefaultSources = []Source{
	{Name: "feodo", URL: FeodoURL, TTL: 48 * time.Hour},
	{Name: "sslbl", URL: SSLBLURL, TTL: 48 * time.Hour},
}

const maxListBytes = 8 << 20

// Updater downloads sources into a cache directory and loads them into a
// Reputation. A failed download falls back to the cached file.
type Updater struct {
	Rep    *Reputation
	Dir    string // cache directory (created as needed)
	Client *http.Client
}

// Refresh updates every source; it returns the first error but tries all.
func (u *Updater) Refresh(ctx context.Context, srcs []Source) error {
	var first error
	for _, s := range srcs {
		if err := u.one(ctx, s); err != nil && first == nil {
			first = fmt.Errorf("%s: %w", s.Name, err)
		}
	}
	return first
}

func (u *Updater) one(ctx context.Context, s Source) error {
	ttl := s.TTL
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	file := filepath.Join(u.Dir, "rep-"+filepath.Base(s.Name)+".txt")
	body, err := u.download(ctx, s.URL)
	if err == nil {
		if mk := os.MkdirAll(u.Dir, 0o700); mk == nil {
			_ = os.WriteFile(file, body, 0o600)
		}
		u.Rep.SetList(s.Name, ParseList(strings.NewReader(string(body))), u.Rep.now().Add(ttl))
		return nil
	}
	// fall back to cache; expiry counts from the file's age
	st, serr := os.Stat(file)
	if serr != nil {
		return err
	}
	f, oerr := os.Open(file)
	if oerr != nil {
		return err
	}
	defer f.Close()
	u.Rep.SetList(s.Name, ParseList(f), st.ModTime().Add(ttl))
	return err
}

func (u *Updater) download(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	cl := u.Client
	if cl == nil {
		cl = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxListBytes))
}
