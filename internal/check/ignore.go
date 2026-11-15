package check

// Hiding warnings ("I know, leave me alone"): a user may hide a finding or a
// notice for a day, a week or for good. Draft (Bob, 2026-11-15):
//
//  1. Only notes about the user's own, deliberate configuration can be
//     hidden (list hideable below); never anything at level "bad", never a
//     state of the moment (tunnel down, DNS fails, login page, clock, pass,
//     panic, Tor emergency) and never a leak path (DNS off, DoH, kill
//     switch, boot lockdown, nsswitch, start guard): hiding those would
//     look like "all safe".
//  2. A finding has a stable key: its ID, plus the thing it is about
//     (rule, tunnel, network, group): "rule.direct:firefox". Hiding one
//     rule never hides another.
//  3. The list lives in one local JSON file (Linux: state directory or
//     next to the config; Windows: ProgramData\Shunt; Android: the app's
//     own settings). It is never sent anywhere.
//  4. An entry ends by itself (Until); an expired one is dropped.
//  5. The status carries what is hidden ("n hidden" with the list), so it
//     can always be found and taken back.

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// hideable: the finding IDs a user may hide, and the value (in Vals) that
// names what the finding is about ("" = the finding as a whole). Why each
// one is allowed: it describes a choice in the user's own configuration
// that stays true until the config changes, and a person who made it on
// purpose would otherwise see it every day.
var hideable = map[string]string{
	"rule.direct":       "rule",   // apps that go past the tunnel on purpose (printer, banking app)
	"rule.plaindns":     "rule",   // a direct rule with plain DNS: known trade-off
	"default.direct":    "",       // a deliberate default (only while it is not "bad")
	"network.direct":    "link",   // Android: other apps direct on Wi-Fi / mobile data
	"default.block":     "",       // Android: "all other apps are blocked" (the safe side)
	"network.ssid_only": "name",   // a profile known by its name only
	"gateway.direct":    "name",   // a gateway group going out directly
	"gateway.noroute":   "name",   // a gateway group without route (blocked)
	"stealth.unset":     "",       // MAC / host name disguise switched off
	"stealth.home":      "",       // disguise also at home
	"stealth.winname":   "",       // how Windows reads the neutral name
	"quiet.off":         "",       // quiet mode switched off
	"inbound.off":       "",       // inbound protection switched off
	"captive.on":        "",       // the login page check, switched on explicitly
	"filter.redundant":  "",       // tidy-up hint for DNS lists
	"ovpn.cbc":          "tunnel", // provider files the user cannot change
	"ovpn.auth":         "tunnel",
	"ovpn.compress":     "tunnel",
	"ovpn.nowrap":       "tunnel",
	"ovpn.tls":          "tunnel",
	"ovpn.nocerttype":   "tunnel",
}

// Hideable lists the IDs that can be hidden, sorted (docs, tests, the
// Android copy).
func Hideable() []string {
	out := make([]string, 0, len(hideable))
	for id := range hideable {
		out = append(out, id)
	}
	slices.Sort(out)
	return out
}

// HideKey is the key under which f can be hidden; ok is false when f may
// not be hidden (not in the list, or "bad").
func HideKey(f Finding) (key string, ok bool) {
	subj, listed := hideable[f.ID]
	// "bad" is never hidden, with one exception: the strict check raises a
	// note about a provider's OpenVPN file (which the user cannot change) to
	// "bad"; that stays hideable, it was a note to begin with.
	if !listed || (f.Level == Bad && !(f.Strict && strings.HasPrefix(f.ID, "ovpn."))) {
		return "", false
	}
	if subj == "" {
		return f.ID, true
	}
	return f.ID + ":" + f.Vals[subj], true
}

// keyID is the finding ID of a key (IDs never contain ':').
func keyID(key string) string {
	id, _, _ := strings.Cut(key, ":")
	return id
}

// Durations of POST /v1/warnings/ignore ("for").
const (
	ForDay     = "day"
	ForWeek    = "week"
	ForForever = "forever"
)

// ParseFor turns "day", "week" or "forever" into a duration (0 = forever).
func ParseFor(s string) (time.Duration, error) {
	switch s {
	case ForDay:
		return 24 * time.Hour, nil
	case ForWeek:
		return 7 * 24 * time.Hour, nil
	case ForForever, "":
		return 0, nil
	}
	return 0, fmt.Errorf("for: %q is not day, week or forever", s)
}

// Ignored is one hidden warning. ID, Msg and Vals keep the finding as it
// was when it was hidden, so the list can show it while it is not there.
type Ignored struct {
	Key   string            `json:"key"`
	ID    string            `json:"id"`
	Msg   string            `json:"msg"`
	Vals  map[string]string `json:"vals,omitempty"`
	Added time.Time         `json:"added"`
	// Until: when it shows again; zero = never.
	Until time.Time `json:"until,omitzero"`
	// Hiding (status only): a current warning is hidden by it right now.
	Hiding bool `json:"hiding,omitempty"`
}

// ErrNotHideable: the key names a warning that may not be hidden.
var ErrNotHideable = errors.New("this warning cannot be hidden")

// IgnoreList is the list of hidden warnings, kept in one file.
type IgnoreList struct {
	path string // "" = memory only
	mu   sync.Mutex
	item map[string]Ignored
	// Now is the clock (tests); nil = time.Now.
	Now func() time.Time
}

// OpenIgnore reads the list at path (a missing file is an empty list). On
// a damaged file the list starts empty and err says why; it is still
// usable and the next change overwrites the file.
func OpenIgnore(path string) (*IgnoreList, error) {
	l := &IgnoreList{path: path, item: map[string]Ignored{}}
	if path == "" {
		return l, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return l, nil
	}
	if err != nil {
		return l, err
	}
	var f struct {
		Ignored []Ignored `json:"ignored"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return l, fmt.Errorf("%s: %w", path, err)
	}
	for _, it := range f.Ignored {
		if _, ok := hideable[keyID(it.Key)]; ok {
			it.Hiding = false
			l.item[it.Key] = it
		}
	}
	return l, nil
}

func (l *IgnoreList) now() time.Time {
	if l.Now != nil {
		return l.Now()
	}
	return time.Now()
}

// pruneLocked drops expired entries and reports whether one went.
func (l *IgnoreList) pruneLocked(now time.Time) bool {
	gone := false
	for k, it := range l.item {
		if !it.Until.IsZero() && !now.Before(it.Until) {
			delete(l.item, k)
			gone = true
		}
	}
	return gone
}

func (l *IgnoreList) sortedLocked() []Ignored {
	out := make([]Ignored, 0, len(l.item))
	for _, it := range l.item {
		out = append(out, it)
	}
	slices.SortFunc(out, func(a, b Ignored) int { return cmp.Compare(a.Key, b.Key) })
	return out
}

func (l *IgnoreList) saveLocked() error {
	if l.path == "" {
		return nil
	}
	b, err := json.MarshalIndent(struct {
		Ignored []Ignored `json:"ignored"`
	}{l.sortedLocked()}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(l.path), 0o755); err != nil {
		return err
	}
	tmp := l.path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, l.path)
}

// Hide hides f for d (0 = for good). It fails for a finding that may not
// be hidden.
func (l *IgnoreList) Hide(f Finding, d time.Duration) (Ignored, error) {
	key, ok := HideKey(f)
	if !ok {
		return Ignored{}, ErrNotHideable
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.pruneLocked(now)
	it := Ignored{Key: key, ID: f.ID, Msg: f.Msg, Vals: f.Vals, Added: now.UTC().Truncate(time.Second)}
	if d > 0 {
		it.Until = now.Add(d).UTC().Truncate(time.Second)
	}
	l.item[key] = it
	return it, l.saveLocked()
}

// Unhide takes key back; false when it was not hidden.
func (l *IgnoreList) Unhide(key string) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, ok := l.item[key]
	delete(l.item, key)
	gone := l.pruneLocked(l.now())
	if !ok && !gone {
		return false, nil
	}
	return ok, l.saveLocked()
}

// List returns the entries in effect, sorted by key.
func (l *IgnoreList) List() []Ignored {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.pruneLocked(l.now()) {
		_ = l.saveLocked()
	}
	return l.sortedLocked()
}

// Filter splits fs into what is shown and what is hidden. Shown findings
// that could be hidden get their Key, so a front end can offer the button.
// A finding at level "bad" is always shown, even if its key is listed
// (except a strict-raised OpenVPN file note, see HideKey).
func (l *IgnoreList) Filter(fs []Finding) (shown, hidden []Finding) {
	var on map[string]Ignored
	if l != nil {
		l.mu.Lock()
		l.pruneLocked(l.now())
		on = l.item
		defer l.mu.Unlock()
	}
	for _, f := range fs {
		key, ok := HideKey(f)
		if !ok {
			shown = append(shown, f)
			continue
		}
		if _, hide := on[key]; hide {
			hidden = append(hidden, f)
			continue
		}
		f.Key = key
		shown = append(shown, f)
	}
	return shown, hidden
}
