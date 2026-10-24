package winapps

import (
	"os"
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/api"
	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/Bob-Nixkoenner/the_shunt/internal/desktop"
)

// Runs on a real Windows machine (go test -c, copy, run): the Start menu and
// the process list must give something sensible.
func TestLiveStartMenuAndProcesses(t *testing.T) {
	sm := StartMenu()
	t.Logf("%d Start menu programs", len(sm))
	for i, p := range sm {
		if i < 12 {
			t.Logf("  %-30s %s", p.Name, p.Path)
		}
	}
	if len(sm) == 0 {
		t.Error("no Start menu programs found")
	}
	ps := Running()
	t.Logf("%d running programs", len(ps))
	if len(ps) < 5 {
		t.Error("too few processes")
	}
}

// SHUNT_LIVE_LAUNCHER=<route>: makes a real launcher "Brave Test" with a new
// profile folder (Start menu shortcut, launchers.json).
func TestLiveProfileLauncher(t *testing.T) {
	route := os.Getenv("SHUNT_LIVE_LAUNCHER")
	if route == "" {
		t.Skip("SHUNT_LIVE_LAUNCHER not set")
	}
	home, _ := os.UserHomeDir()
	for _, x := range desktop.ChromiumProfiles() {
		t.Logf("profile %+v", x)
		if _, err := desktop.ChromiumInstance(home, x, "x"); err != desktop.ErrSharedProfile {
			t.Errorf("existing profile shared: %v", err)
		}
	}
	s := &Source{Client: nilAPI{}, Self: `C:\Program Files\The Shunt\shunt-desktop.exe`}
	dir := desktop.InstanceDir(home, "Brave Test")
	id, err := s.Clone("brave.exe", "Brave Test", `--user-data-dir="`+dir+`"`, route)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("launcher %s, folder %s", id, dir)
}

type nilAPI struct{}

func (nilAPI) Do(method, path string, in, out any) error {
	if v, ok := out.(*api.ConfigView); ok {
		*v = api.ConfigView{Config: &config.Config{}}
	}
	return nil
}
