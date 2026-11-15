package check

import (
	"errors"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func direct(rule string) Finding {
	return Finding{ID: "rule.direct", Level: Info, Msg: "Rule “{rule}” sends traffic direct, past every tunnel.", Vals: map[string]string{"rule": rule}}
}

func TestHideKey(t *testing.T) {
	for _, c := range []struct {
		f   Finding
		key string
	}{
		{direct("firefox"), "rule.direct:firefox"},
		{Finding{ID: "quiet.off", Level: Info}, "quiet.off"},
		{Finding{ID: "ovpn.nowrap", Level: Warn, Vals: map[string]string{"tunnel": "vpn"}}, "ovpn.nowrap:vpn"},
		// bad is never hidden, whatever the ID (strict check raises it)
		{Finding{ID: "ovpn.nowrap", Level: Bad, Vals: map[string]string{"tunnel": "vpn"}}, ""},
		{Finding{ID: "default.direct", Level: Bad}, ""},
		// ... except a provider's OpenVPN file note that only the strict check made bad
		{Finding{ID: "ovpn.nocerttype", Level: Bad, Strict: true, Vals: map[string]string{"tunnel": "vpn"}}, "ovpn.nocerttype:vpn"},
		{Finding{ID: "default.direct", Level: Bad, Strict: true}, ""},
		// states of the moment and leak paths are never hidden
		{Note("captive", "Wi-Fi login page in the way{ssid}", "ssid", ""), ""},
		{Note("clock", "clock"), ""},
		{Note("dns.fails", "DNS for {route} fails ({error}).", "route", "direct", "error", "x"), ""},
		{Note("nsswitch", "nsswitch"), ""},
		{Note("startguard", "start guard"), ""},
		{Note("pass", "Pass"), ""},
		{Finding{ID: "dns.doh", Level: Warn}, ""},
		{Finding{ID: "bootlock.off", Level: Warn}, ""},
		{Finding{ID: "killswitch.off", Level: Warn}, ""},
		{Raw("anything"), ""},
	} {
		key, ok := HideKey(c.f)
		if key != c.key || ok != (c.key != "") {
			t.Errorf("%s/%s: key %q %v, want %q", c.f.ID, c.f.Level, key, ok, c.key)
		}
	}
}

// Every hideable ID exists (in the check, as a notice or on Android) and
// names a value its findings carry.
func TestHideableIDsKnown(t *testing.T) {
	known := map[string]bool{"rule.plaindns": true, "filter.redundant": true, "network.direct": true, "default.block": true}
	for _, id := range allIDs {
		known[id] = true
	}
	for _, id := range Hideable() {
		if !known[id] {
			t.Errorf("hideable %q is no finding", id)
		}
	}
}

func clock(t *time.Time) func() time.Time { return func() time.Time { return *t } }

func TestIgnoreExpires(t *testing.T) {
	now := time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)
	l, _ := OpenIgnore("")
	l.Now = clock(&now)
	if _, err := l.Hide(direct("a"), 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Hide(direct("b"), 0); err != nil {
		t.Fatal(err)
	}
	fs := []Finding{direct("a"), direct("b"), direct("c")}
	shown, hidden := l.Filter(fs)
	if len(shown) != 1 || shown[0].Vals["rule"] != "c" || shown[0].Key != "rule.direct:c" || len(hidden) != 2 {
		t.Fatalf("shown %v hidden %v", shown, hidden)
	}
	now = now.Add(24*time.Hour - time.Second)
	if _, hidden := l.Filter(fs); len(hidden) != 2 {
		t.Fatalf("before the end: hidden %v", hidden)
	}
	now = now.Add(time.Second)
	shown, hidden = l.Filter(fs)
	if len(hidden) != 1 || hidden[0].Vals["rule"] != "b" || len(shown) != 2 {
		t.Fatalf("after a day: shown %v hidden %v", shown, hidden)
	}
	if ls := l.List(); len(ls) != 1 || ls[0].Key != "rule.direct:b" || !ls[0].Until.IsZero() {
		t.Fatalf("list %+v", ls)
	}
	now = now.Add(10 * 365 * 24 * time.Hour)
	if _, hidden := l.Filter(fs); len(hidden) != 1 {
		t.Fatal("for good ended")
	}
}

func TestIgnoreRefusesAndKeepsBad(t *testing.T) {
	l, _ := OpenIgnore("")
	if _, err := l.Hide(Note("captive", "x"), 0); !errors.Is(err, ErrNotHideable) {
		t.Fatalf("captive: %v", err)
	}
	if _, err := l.Hide(Finding{ID: "default.direct", Level: Bad}, 0); !errors.Is(err, ErrNotHideable) {
		t.Fatalf("bad: %v", err)
	}
	// hidden while it was a note; the strict check makes it bad: it shows
	if _, err := l.Hide(Finding{ID: "default.direct", Level: Info}, 0); err != nil {
		t.Fatal(err)
	}
	shown, hidden := l.Filter([]Finding{{ID: "default.direct", Level: Bad}})
	if len(shown) != 1 || len(hidden) != 0 || shown[0].Key != "" {
		t.Fatalf("bad hidden: shown %v hidden %v", shown, hidden)
	}
	// a nil list hides nothing but marks
	shown, _ = (*IgnoreList)(nil).Filter([]Finding{direct("x")})
	if shown[0].Key != "rule.direct:x" {
		t.Fatalf("nil list: %v", shown)
	}
}

func TestIgnorePersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "ignored.json")
	now := time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)
	l, err := OpenIgnore(path)
	if err != nil {
		t.Fatal(err)
	}
	l.Now = clock(&now)
	if _, err := l.Hide(direct("a"), 7*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Hide(Finding{ID: "quiet.off", Level: Info, Msg: "q"}, 0); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("file: %v %v", fi, err)
	}
	l2, err := OpenIgnore(path)
	if err != nil {
		t.Fatal(err)
	}
	l2.Now = clock(&now)
	ls := l2.List()
	if len(ls) != 2 || ls[0].Key != "quiet.off" || ls[1].Key != "rule.direct:a" || ls[1].Msg == "" || ls[1].Vals["rule"] != "a" ||
		!ls[1].Until.Equal(now.Add(7*24*time.Hour)) {
		t.Fatalf("reloaded %+v", ls)
	}
	if ok, err := l2.Unhide("quiet.off"); !ok || err != nil {
		t.Fatalf("unhide: %v %v", ok, err)
	}
	if ok, _ := l2.Unhide("quiet.off"); ok {
		t.Fatal("unhid twice")
	}
	l3, _ := OpenIgnore(path)
	l3.Now = clock(&now)
	if ls := l3.List(); len(ls) != 1 {
		t.Fatalf("after unhide %+v", ls)
	}
	// an expired entry is dropped from the file too
	now = now.Add(8 * 24 * time.Hour)
	if ls := l3.List(); len(ls) != 0 {
		t.Fatalf("expired %+v", ls)
	}
	l4, _ := OpenIgnore(path)
	if len(l4.item) != 0 {
		t.Fatalf("expired kept in file: %+v", l4.item)
	}
}

func TestIgnoreDamagedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ignored.json")
	os.WriteFile(path, []byte("{nope"), 0o600)
	l, err := OpenIgnore(path)
	if err == nil || l == nil {
		t.Fatalf("damaged: %v %v", l, err)
	}
	if _, err := l.Hide(direct("a"), 0); err != nil {
		t.Fatal(err)
	}
	// an entry for an ID that may no longer be hidden is not loaded
	os.WriteFile(path, []byte(`{"ignored":[{"key":"captive","id":"captive"},{"key":"rule.direct:a","id":"rule.direct"}]}`), 0o600)
	l, err = OpenIgnore(path)
	if err != nil || len(l.List()) != 1 {
		t.Fatalf("filtered load: %v %+v", err, l.List())
	}
}

func TestParseFor(t *testing.T) {
	for s, want := range map[string]time.Duration{"day": 24 * time.Hour, "week": 7 * 24 * time.Hour, "forever": 0} {
		if d, err := ParseFor(s); err != nil || d != want {
			t.Errorf("%s: %v %v", s, d, err)
		}
	}
	if _, err := ParseFor("month"); err == nil {
		t.Error("month accepted")
	}
}

// The Android app has its own copy of the list (HiddenWarnings.HIDEABLE in
// Hidden.kt): it must say the same.
func TestHideableSameOnAndroid(t *testing.T) {
	b, err := os.ReadFile("../../android/app/src/main/java/org/theshunt/app/Hidden.kt")
	if err != nil {
		t.Skip(err)
	}
	src := string(b)
	i := strings.Index(src, "val HIDEABLE = mapOf(")
	j := strings.Index(src[i:], "\n    )")
	if i < 0 || j < 0 {
		t.Fatal("HIDEABLE not found in Hidden.kt")
	}
	kt := map[string]string{}
	for _, m := range regexp.MustCompile(`"([^"]+)" to "([^"]*)"`).FindAllStringSubmatch(src[i:i+j], -1) {
		kt[m[1]] = m[2]
	}
	if !maps.Equal(kt, hideable) {
		t.Fatalf("Android %v\ndesktop %v", kt, hideable)
	}
}
