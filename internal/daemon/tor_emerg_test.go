package daemon

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/engine"
)

type emergBackend struct {
	*fakeBackend
	group engine.Group
	dst   []netip.Prefix
	gone  bool // the emergency table was removed from outside
}

func (e *emergBackend) Emergency(g engine.Group, dst []netip.Prefix) (string, error) {
	e.group, e.dst = g, dst
	return "emergency-on", nil
}
func (e *emergBackend) EmergencyOff() string  { return "emergency-off" }
func (e *emergBackend) EmergencyIntact() bool { return !e.gone }

func TestRulesIntactWatchesEmergencyTable(t *testing.T) {
	eb := &emergBackend{fakeBackend: newFake()}
	d := &Daemon{Backend: eb, prep: &Prepared{}}
	eb.gone = true
	if !d.rulesIntact() {
		t.Error("tor-all off: a missing emergency table is fine")
	}
	d.prep.EmergOn = true
	if d.rulesIntact() {
		t.Error("tor-all on: missing emergency table must count as removed")
	}
	eb.gone = false
	if !d.rulesIntact() {
		t.Error("everything there: intact")
	}
	eb.flushed = true
	if d.rulesIntact() {
		t.Error("main table removed: not intact")
	}
}

type fakeRuleset struct{ *emergBackend }

func (f fakeRuleset) Render(*engine.Plan) (string, error) { return "main", nil }

func emergEnv(t *testing.T, conf string) (string, *emergBackend) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "shunt.toml")
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	old := torDataRoot
	torDataRoot = filepath.Join(dir, "tor")
	t.Cleanup(func() { torDataRoot = old })
	return path, &emergBackend{fakeBackend: newFake()}
}

func TestTorAllEmergency(t *testing.T) {
	const conf = "[daemon]\nsocket = \"/nonexistent/s.sock\"\n[tunnel.tor]\ndriver = \"tor\"\n"
	path, eb := emergEnv(t, conf)
	be := fakeRuleset{eb}
	cons := "r A id 2026-10-30 10:00:00 192.0.2.1 9001 0\na [2001:db8::1]:9001\n"
	if err := os.MkdirAll(filepath.Join(torDataRoot, "tor"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(torDataRoot, "tor", "cached-microdesc-consensus"), []byte(cons), 0o600); err != nil {
		t.Fatal(err)
	}

	// off: the emergency table is removed with every reload
	p, err := PrepareOn(path, "shunt", Env{Backend: be})
	if err != nil || !strings.HasSuffix(p.Ruleset, "emergency-off") {
		t.Fatalf("off: %v %q", err, p.Ruleset)
	}
	// on: strict part in the same script, only the daemon group (tor), only relays
	p, err = PrepareOn(path, "shunt", Env{Backend: be, TorAll: "tor"})
	if err != nil || !strings.HasSuffix(p.Ruleset, "emergency-on") || !strings.HasPrefix(p.Ruleset, "main") {
		t.Fatalf("on: %v %q", err, p.Ruleset)
	}
	if !p.EmergOn {
		t.Error("EmergOn not set")
	}
	if eb.group.Path != p.Plan.DaemonGroup.Path || len(eb.dst) != 2 || p.EmergKey == "" {
		t.Errorf("group %v dst %v key %q", eb.group, eb.dst, p.EmergKey)
	}

	// bridges win over the consensus; hidden ones open the tor process only
	c2 := conf + "bridges = [\"obfs4 203.0.113.9:443 FP cert=x\"]\n"
	if err := os.WriteFile(path, []byte(c2), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = PrepareOn(path, "shunt", Env{Backend: be, TorAll: "tor"}); err != nil || len(eb.dst) != 1 || eb.dst[0].String() != "203.0.113.9/32" {
		t.Errorf("bridge: %v %v", err, eb.dst)
	}
	if err := os.WriteFile(path, []byte(conf+"bridges = [\"snowflake\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err = PrepareOn(path, "shunt", Env{Backend: be, TorAll: "tor"})
	if err != nil || len(eb.dst) != 2 || eb.dst[0].Bits() != 0 {
		t.Errorf("snowflake: %v %v", err, eb.dst)
	}

	// no relay list, no bridges: nothing gets out (empty destinations), with a note
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(filepath.Join(torDataRoot, "tor", "cached-microdesc-consensus"))
	p, err = PrepareOn(path, "shunt", Env{Backend: be, TorAll: "tor"})
	if err != nil || len(eb.dst) != 0 || !strings.HasSuffix(p.Ruleset, "emergency-on") {
		t.Errorf("empty: %v %v", err, eb.dst)
	}
	// switching on is refused then (tor could never start)
	d := &Daemon{ConfigPath: path, Backend: be, cfg: p.Config}
	if err := d.setTorAll(true, ""); err == nil || !strings.Contains(err.Error(), "relays") {
		t.Errorf("setTorAll without relay list: %v", err)
	}
}

// A backend without strict rules keeps the old tor-all and says so.
func TestTorAllNoStrictBackend(t *testing.T) {
	path, _ := emergEnv(t, "[daemon]\nsocket = \"/nonexistent/s.sock\"\n[tunnel.tor]\ndriver = \"tor\"\n")
	p, err := PrepareOn(path, "shunt", Env{Backend: newFake(), TorAll: "tor"})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, n := range p.Notes {
		found = found || n.ID == "tor.nostrict"
	}
	if !found {
		t.Error("no note about the missing strict mode")
	}
}
