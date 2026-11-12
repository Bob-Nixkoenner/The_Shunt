package daemon

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A config that kills shuntd at every start (simulated: begin without done,
// as a panic or SIGSYS leaves it) is replaced by the previous one after
// three starts; the old one never comes back by itself.
func TestStartGuardRestoresAfterFailedStarts(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("STATE_DIRECTORY", dir)
	cfg := filepath.Join(dir, "shunt.toml")
	good, bad := "# good\n", "# bad: crashes at start\n"
	must(t, os.WriteFile(cfg+".bak", []byte(good), 0o644))
	must(t, os.WriteFile(cfg, []byte(bad), 0o644))
	newD := func() *Daemon { return &Daemon{ConfigPath: cfg, Log: slog.New(slog.NewTextHandler(io.Discard, nil))} }

	for i := 1; i <= startGuardTries; i++ { // the crash loop
		d := newD()
		d.startGuardBegin()
		if got := read(t, cfg); got != bad || d.startRestored != 0 {
			t.Fatalf("start %d: config %q restored %d, want the new one kept", i, got, d.startRestored)
		}
	}
	d := newD()
	d.startGuardBegin()
	if got := read(t, cfg); got != good {
		t.Fatalf("after %d failed starts the config is %q, want the previous one", startGuardTries, got)
	}
	if got := read(t, cfg+".failed"); got != bad {
		t.Errorf("failed config kept as %q", got)
	}
	n := d.startGuardNote()
	if len(n) != 1 || n[0].ID != "config.restored" || !strings.Contains(n[0].Vals["file"], ".failed") {
		t.Errorf("notice = %+v", n)
	}
	// the previous config fails as well: it stays, no ping-pong to the bad one
	must(t, os.WriteFile(cfg+".bak", []byte(good), 0o644)) // as after a restore
	for i := 0; i < 2*startGuardTries; i++ {
		newD().startGuardBegin()
	}
	if got := read(t, cfg); got != good {
		t.Errorf("config went to %q", got)
	}
}

// Starts that got through reset the count; without a different .bak
// nothing is touched.
func TestStartGuardLeavesWorkingConfigs(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("STATE_DIRECTORY", dir)
	cfg := filepath.Join(dir, "shunt.toml")
	must(t, os.WriteFile(cfg, []byte("# a\n"), 0o644))
	must(t, os.WriteFile(cfg+".bak", []byte("# old\n"), 0o644))
	d := &Daemon{ConfigPath: cfg, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	for i := 0; i < 3*startGuardTries; i++ { // many restarts, each one settles
		d.startGuardBegin()
		d.startGuardDone()
	}
	if read(t, cfg) != "# a\n" || d.startRestored != 0 {
		t.Fatal("a config whose starts get through was replaced")
	}
	// no different previous config: the loop goes on, nothing is replaced
	must(t, os.WriteFile(cfg+".bak", []byte("# a\n"), 0o644))
	for i := 0; i < 2*startGuardTries; i++ {
		d.startGuardBegin()
	}
	if read(t, cfg) != "# a\n" {
		t.Fatal("config changed without a different .bak")
	}
	if _, err := os.Stat(cfg + ".failed"); err == nil {
		t.Error(".failed written without a restore")
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
