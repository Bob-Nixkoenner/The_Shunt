package evidence

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newLog(t *testing.T, c *clock, mut func(*Options)) (*Log, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "evidence")
	o := Options{Version: "v0-test", Now: c.now}
	if mut != nil {
		mut(&o)
	}
	l, err := Open(dir, o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l, dir
}

func TestLogChainAndModes(t *testing.T) {
	c := &clock{time.Date(2026, 11, 11, 8, 0, 0, 0, time.UTC)}
	l, dir := newLog(t, c, nil)
	l.SetNetClass("public")
	for i := 0; i < 5; i++ {
		c.t = c.t.Add(time.Second)
		if _, err := l.Append(Input{Kind: "decoy_hit", Severity: "medium", Src: "192.0.2.7", Port: 22, Proto: "tcp", Detail: "x"}); err != nil {
			t.Fatal(err)
		}
	}
	if r := Verify(dir); !r.OK || r.Lines != 5 {
		t.Fatalf("verify: %+v", r)
	}
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v", fi.Mode())
	}
	names, _ := listLogFiles(dir)
	if fi, _ := os.Stat(filepath.Join(dir, names[0])); fi.Mode().Perm() != 0o600 {
		t.Fatalf("file mode %v", fi.Mode())
	}
	es, _ := l.Read(Filter{})
	if es[0].PrevHash != ZeroHash || es[1].PrevHash != es[0].Hash || es[0].NetClass != "public" || es[0].ShuntVersion != "v0-test" {
		t.Fatalf("chain fields: %+v", es[:2])
	}
	if !strings.HasSuffix(es[0].TimeUTC, "Z") {
		t.Fatal("time is not UTC")
	}
}

func TestVerifyFindsTampering(t *testing.T) {
	c := &clock{time.Date(2026, 11, 11, 8, 0, 0, 0, time.UTC)}
	l, dir := newLog(t, c, nil)
	for i := 0; i < 6; i++ {
		_, _ = l.Append(Input{Kind: "scan", Severity: "high", Src: "198.51.100.9", Detail: "n"})
	}
	l.Close()
	names, _ := listLogFiles(dir)
	p := filepath.Join(dir, names[0])
	orig, _ := os.ReadFile(p)
	lines := strings.Split(strings.TrimSpace(string(orig)), "\n")

	cases := map[string]func() string{
		"edited field": func() string {
			l := append([]string{}, lines...)
			l[2] = strings.Replace(l[2], "198.51.100.9", "198.51.100.1", 1)
			return strings.Join(l, "\n") + "\n"
		},
		"deleted line": func() string {
			l := append([]string{}, lines[:2]...)
			l = append(l, lines[3:]...)
			return strings.Join(l, "\n") + "\n"
		},
		"swapped lines": func() string {
			l := append([]string{}, lines...)
			l[1], l[2] = l[2], l[1]
			return strings.Join(l, "\n") + "\n"
		},
		"cut at end":   func() string { return strings.Join(lines[:4], "\n") + "\n" },
		"garbage line": func() string { l := append([]string{}, lines...); l[3] = "{}"; return strings.Join(l, "\n") + "\n" },
	}
	for name, mk := range cases {
		if err := os.WriteFile(p, []byte(mk()), 0o600); err != nil {
			t.Fatal(err)
		}
		r := Verify(dir)
		if r.OK || r.FirstBad == "" {
			t.Errorf("%s: tampering not found: %+v", name, r)
		}
	}
	_ = os.WriteFile(p, orig, 0o600)
	if r := Verify(dir); !r.OK {
		t.Fatalf("restored log fails: %+v", r)
	}
	// first bad line is named
	bad := strings.Replace(string(orig), "198.51.100.9", "198.51.100.8", 2)
	_ = os.WriteFile(p, []byte(bad), 0o600)
	if r := Verify(dir); !strings.Contains(r.FirstBad, ":1:") {
		t.Fatalf("first bad line not reported: %q", r.FirstBad)
	}
}

func TestRotationKeepsChainAcrossFilesAndRestart(t *testing.T) {
	c := &clock{time.Date(2026, 11, 11, 23, 59, 58, 0, time.UTC)}
	l, dir := newLog(t, c, func(o *Options) { o.MaxFileBytes = 600 })
	for i := 0; i < 10; i++ {
		_, _ = l.Append(Input{Kind: "observation", Severity: "info", Detail: strings.Repeat("a", 40)})
	}
	c.t = c.t.Add(5 * time.Second) // next day
	_, _ = l.Append(Input{Kind: "observation", Severity: "info"})
	l.Close()
	names, _ := listLogFiles(dir)
	if len(names) < 3 {
		t.Fatalf("expected rotation by size and by day, got %v", names)
	}
	// reopen: numbering and chain go on
	l2, err := Open(dir, Options{Version: "v1", Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	seq, _ := l2.Append(Input{Kind: "observation", Severity: "info"})
	l2.Close()
	if seq != 12 {
		t.Fatalf("seq after restart %d", seq)
	}
	if r := Verify(dir); !r.OK || r.Lines != 12 {
		t.Fatalf("%+v", r)
	}
	// a file removed behind the manifest's back is found
	_ = os.Remove(filepath.Join(dir, names[1]))
	if r := Verify(dir); r.OK {
		t.Fatal("silently deleted file not found")
	}
}

func TestPreambleWrittenIntoEveryFile(t *testing.T) {
	c := &clock{time.Date(2026, 11, 11, 8, 0, 0, 0, time.UTC)}
	l, dir := newLog(t, c, func(o *Options) {
		o.Preamble = func() []Input {
			return []Input{{Kind: "state_clock", Severity: "info", Detail: "ntp_synchronized=yes"}}
		}
	})
	_, _ = l.Append(Input{Kind: "scan", Severity: "high"})
	c.t = c.t.Add(24 * time.Hour)
	_, _ = l.Append(Input{Kind: "scan", Severity: "high"})
	es, _ := l.Read(Filter{})
	if len(es) != 4 || es[0].Kind != "state_clock" || es[2].Kind != "state_clock" {
		t.Fatalf("%+v", es)
	}
	if r := Verify(dir); !r.OK {
		t.Fatal(r)
	}
}

func TestPruneRetentionPinnedAndPurge(t *testing.T) {
	c := &clock{time.Date(2026, 1, 1, 8, 0, 0, 0, time.UTC)}
	l, dir := newLog(t, c, nil)
	cs, _ := OpenCases(dir)
	for d := 0; d < 6; d++ { // six days, one line each
		_, _ = l.Append(Input{Kind: "scan", Severity: "high", Src: "192.0.2.1"})
		c.t = c.t.Add(24 * time.Hour)
	}
	// pin a case that holds seq 2
	cs.list = append(cs.list, Case{ID: "aa", Src: "192.0.2.1", FromSeq: 2, ToSeq: 2, Pinned: true})
	c.t = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC) // far later: all older than 90 days
	n, err := l.Prune(90*24*time.Hour, 0, cs.Protects)
	if err != nil {
		t.Fatal(err)
	}
	// last file is open: kept; pinned file kept; 4 deleted
	if n != 4 {
		t.Fatalf("removed %d", n)
	}
	r := Verify(dir)
	if !r.OK || r.Lines != 2 {
		t.Fatalf("after prune: %+v", r)
	}
	if len(r.Notes) == 0 {
		t.Fatal("removal not noted")
	}
	// purge without the flag keeps the pinned case; with it everything goes
	if _, err := l.Purge(false, cs.Protects); err != nil {
		t.Fatal(err)
	}
	if r := Verify(dir); !r.OK || r.Lines != 1 {
		t.Fatalf("purge: %+v", r)
	}
	if _, err := l.Purge(true, cs.Protects); err != nil {
		t.Fatal(err)
	}
	if r := Verify(dir); !r.OK || r.Lines != 0 {
		t.Fatalf("purge all: %+v", r)
	}
	seq, _ := l.Append(Input{Kind: "scan", Severity: "low"})
	if seq != 7 {
		t.Fatalf("numbering must go on after a purge, got %d", seq)
	}
	if r := Verify(dir); !r.OK {
		t.Fatal(r)
	}
}

func TestPruneBySize(t *testing.T) {
	c := &clock{time.Date(2026, 11, 1, 8, 0, 0, 0, time.UTC)}
	l, dir := newLog(t, c, func(o *Options) { o.MaxFileBytes = 300 })
	for i := 0; i < 12; i++ {
		_, _ = l.Append(Input{Kind: "scan", Severity: "low", Detail: strings.Repeat("b", 60)})
	}
	before := dirSize(dir)
	n, _ := l.Prune(0, before/2, nil)
	if n == 0 || dirSize(dir) > before {
		t.Fatalf("nothing pruned (%d)", n)
	}
	if r := Verify(dir); !r.OK {
		t.Fatal(r)
	}
}

func TestSafeDirRefusesSymlink(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	_ = os.Mkdir(real, 0o700)
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skip(err)
	}
	if _, err := Open(link, Options{}); err == nil {
		t.Fatal("symlinked evidence dir accepted")
	}
}

func TestParseLineStrict(t *testing.T) {
	line, _, _ := encodeLine(Entry{Seq: 1, TimeUTC: "2026-11-11T08:00:00Z", Kind: "scan", Severity: "low", ShuntVersion: "v", NetClass: "public", PrevHash: ZeroHash})
	if _, err := ParseLine(line); err != nil {
		t.Fatal(err)
	}
	// same fields with extra spaces: hash input differs -> refused
	if _, err := ParseLine(strings.Replace(line, `"seq":1,`, `"seq": 1,`, 1)); err == nil {
		t.Fatal("non-canonical line accepted")
	}
	if _, err := ParseLine(line + " "); err == nil {
		t.Fatal("trailing junk accepted")
	}
}

func FuzzParseLine(f *testing.F) {
	line, _, _ := encodeLine(Entry{Seq: 1, TimeUTC: "2026-11-11T08:00:00Z", Kind: "scan", Severity: "low", ShuntVersion: "v", NetClass: "public", PrevHash: ZeroHash})
	f.Add(line)
	f.Add(`{"hash":"` + strings.Repeat("0", 64) + `"}`)
	f.Fuzz(func(t *testing.T, s string) {
		e, err := ParseLine(s)
		if err == nil {
			// anything accepted must re-encode to the same line
			again, _, _ := encodeLine(e)
			if again != s {
				t.Fatalf("accepted a line that does not round-trip: %q", s)
			}
		}
	})
}
