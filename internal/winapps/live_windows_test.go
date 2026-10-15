package winapps

import "testing"

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
