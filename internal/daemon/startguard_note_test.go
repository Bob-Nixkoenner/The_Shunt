package daemon

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/check"
	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/Bob-Nixkoenner/the_shunt/internal/i18n"
	"github.com/Bob-Nixkoenner/the_shunt/internal/racebpf"
)

// A missing start guard must never be silent while something relies on it,
// and the advice must match the reason (capabilities, memlock, kernel).
func TestStartGuardFinding(t *testing.T) {
	noCaps := fmt.Errorf("x: %w", racebpf.ErrNoCaps)
	memlock := fmt.Errorf("map shunt_names: %w", racebpf.ErrMemlock)
	other := errors.New("program shunt_sock: invalid argument")
	for _, c := range []struct {
		name     string
		err      error
		apps     bool
		fw       string
		want     bool
		level    string
		contains string
	}{
		{"loaded", nil, true, config.FirewallAsk, false, "", ""},
		{"nothing relies on it", other, false, config.FirewallOff, false, "", ""},
		{"app rules", other, true, config.FirewallOff, true, check.Warn, "6.1"},
		{"firewall ask alone", noCaps, false, config.FirewallAsk, true, check.Bad, "CAP_BPF"},
		{"firewall block", memlock, true, config.FirewallBlock, true, check.Bad, "LimitMEMLOCK"},
		{"no caps, app rules", noCaps, true, "", true, check.Warn, "CapabilityBoundingSet"},
	} {
		f, ok := startGuardFinding(c.err, c.apps, c.fw)
		if ok != c.want {
			t.Errorf("%s: shown %v, want %v", c.name, ok, c.want)
			continue
		}
		if !ok {
			continue
		}
		if f.ID != "startguard" || f.Level != c.level || !strings.Contains(f.Text(), c.contains) {
			t.Errorf("%s: %+v", c.name, f)
		}
		if f.Vals["err"] != c.err.Error() {
			t.Errorf("%s: err value %q", c.name, f.Vals["err"])
		}
		if _, ok := i18n.Dict("de")[f.Msg]; !ok {
			t.Errorf("%s: no German text for %q", c.name, f.Msg)
		}
	}
}
