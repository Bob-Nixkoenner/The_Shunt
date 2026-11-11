package defense

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"encoding/hex"
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
	// SSLBLJA3URL: CSV "ja3_md5,Firstseen,Lastseen,Listingreason" (checked
	// 2026-11-11). Optional source "sslbl_ja3".
	SSLBLJA3URL = "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv"
	// ETCompromisedURL: bare IPv4 per line, "---" first line. Optional
	// source "et_compromised"; see docs/DEFENSE.md for the licence notes.
	ETCompromisedURL = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
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

// ParseJA3List reads JA3 digests (32 hex characters, first CSV field).
func ParseJA3List(r io.Reader) map[string]struct{} {
	out := map[string]struct{}{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexByte(line, ','); i >= 0 {
			line = line[:i]
		}
		line = strings.ToLower(line)
		if len(line) != 32 {
			continue
		}
		if _, err := hex.DecodeString(line); err == nil {
			out[line] = struct{}{}
		}
	}
	return out
}

type ja3List struct {
	set     map[string]struct{}
	expires time.Time
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
	ja3   map[string]*ja3List
	stat  map[string]SourceStat
	now   func() time.Time
}

// SourceStat is what the last download of one source did.
type SourceStat struct {
	Entries int
	Updated time.Time
	Error   string
}

// SetStat records the outcome of a download for source name.
func (r *Reputation) SetStat(name string, st SourceStat) {
	r.mu.Lock()
	r.stat[name] = st
	r.mu.Unlock()
}

// Stat returns the recorded outcome for name (zero if never tried).
func (r *Reputation) Stat(name string) SourceStat {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.stat[name]
}

// NewReputation returns an empty set.
func NewReputation() *Reputation {
	return &Reputation{lists: map[string]*repList{}, ja3: map[string]*ja3List{}, stat: map[string]SourceStat{}, now: time.Now}
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

// SetJA3List replaces JA3 list name (zero expires = never).
func (r *Reputation) SetJA3List(name string, set map[string]struct{}, expires time.Time) {
	r.mu.Lock()
	r.ja3[name] = &ja3List{set: set, expires: expires}
	r.mu.Unlock()
}

// LookupJA3 returns the name of an unexpired JA3 list holding hash.
func (r *Reputation) LookupJA3(hash string) (string, bool) {
	now := r.now()
	hash = strings.ToLower(hash)
	r.mu.RLock()
	defer r.mu.RUnlock()
	for name, l := range r.ja3 {
		if !l.expires.IsZero() && !now.Before(l.expires) {
			continue
		}
		if _, ok := l.set[hash]; ok {
			return name, true
		}
	}
	return "", false
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
	for n, l := range r.ja3 {
		if !l.expires.IsZero() && !now.Before(l.expires) {
			delete(r.ja3, n)
		}
	}
	r.mu.Unlock()
}

// Source is a downloadable list.
type Source struct {
	Name string
	URL  string
	TTL  time.Duration // how long its entries count after a download (default 24 h)
	JA3  bool          // the list holds JA3 digests, not addresses
}

// Optional sources: off unless named in Config.ReputationSources. Nothing
// here is downloaded by default.
var OptionalSources = map[string]Source{
	"sslbl_ja3":      {Name: "sslbl_ja3", URL: SSLBLJA3URL, TTL: 72 * time.Hour, JA3: true},
	"et_compromised": {Name: "et_compromised", URL: ETCompromisedURL, TTL: 48 * time.Hour},
}

// OptionalSourceNames lists the valid names for Config.ReputationSources.
func OptionalSourceNames() []string { return []string{"sslbl_ja3", "et_compromised"} }

// BuiltinSourceNames lists the CC0 lists that run unless named in
// Config.ReputationOff.
func BuiltinSourceNames() []string { return []string{"feodo", "sslbl"} }

// QualityList says whether hits on list name may block a source. Lists with
// known false alarms (et_compromised, and anything else) only report.
func QualityList(name string) bool {
	switch name {
	case "feodo", "sslbl", "sslbl_ja3", SpamhausDROP:
		return true
	}
	return false
}

// SpamhausDROP is documented but not built in: the terms of use grant no
// licence (see docs/DEFENSE.md). It is reported in the status as
// unavailable and can never be switched on.
const SpamhausDROP = "spamhaus_drop"

// SourcesFor returns the built-in sources (minus those named in off) plus
// the chosen optional ones (unknown names are ignored).
func SourcesFor(names, off []string) []Source {
	skip := map[string]bool{}
	for _, n := range off {
		skip[n] = true
	}
	var out []Source
	for _, s := range DefaultSources {
		if !skip[s.Name] {
			out = append(out, s)
		}
	}
	seen := map[string]bool{}
	for _, n := range names {
		if s, ok := OptionalSources[n]; ok && !seen[n] {
			seen[n] = true
			out = append(out, s)
		}
	}
	return out
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
		n := u.load(s, bytes.NewReader(body), u.Rep.now().Add(ttl))
		u.Rep.SetStat(s.Name, SourceStat{Entries: n, Updated: u.Rep.now()})
		return nil
	}
	// fall back to cache; expiry counts from the file's age
	st, serr := os.Stat(file)
	if serr != nil {
		u.Rep.SetStat(s.Name, SourceStat{Error: err.Error()})
		return err
	}
	f, oerr := os.Open(file)
	if oerr != nil {
		u.Rep.SetStat(s.Name, SourceStat{Error: err.Error()})
		return err
	}
	defer f.Close()
	n := u.load(s, f, st.ModTime().Add(ttl))
	u.Rep.SetStat(s.Name, SourceStat{Entries: n, Updated: st.ModTime(), Error: err.Error()})
	return err
}

func (u *Updater) load(s Source, r io.Reader, exp time.Time) int {
	if s.JA3 {
		set := ParseJA3List(r)
		u.Rep.SetJA3List(s.Name, set, exp)
		return len(set)
	}
	p := ParseList(r)
	u.Rep.SetList(s.Name, p, exp)
	return len(p)
}

func (u *Updater) download(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "the-shunt")
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
