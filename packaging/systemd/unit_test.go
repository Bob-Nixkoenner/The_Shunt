// Package systemd_test checks the unit files against what shuntd needs.
package systemd_test

import (
	"os"
	"strings"
	"testing"
)

// unit reads the [Service] settings of shuntd.service; a key that is set
// several times keeps all its values, split at white space.
func unit(t *testing.T) map[string][]string {
	t.Helper()
	b, err := os.ReadFile("shuntd.service")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "[") {
			continue
		}
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			t.Fatalf("line without '=': %q", l)
		}
		out[k] = append(out[k], strings.Fields(v)...)
	}
	return out
}

func has(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// The evidence log reads the clock state with adjtimex (read-only). Max
// Security turns the log on; a unit that does not let the call through
// killed shuntd at every start (SIGSYS, 2026-11-12).
func TestUnitLetsTheClockStateBeRead(t *testing.T) {
	u := unit(t)
	if !has(u["SystemCallFilter"], "adjtimex") {
		t.Error("SystemCallFilter lacks adjtimex: evidence.ClockSynced is killed or refused")
	}
	// ProtectClock adds a filter of its own that refuses the whole @clock
	// group, adjtimex in read-only mode included.
	if has(u["ProtectClock"], "yes") || has(u["ProtectClock"], "true") {
		t.Error("ProtectClock=yes refuses adjtimex even when SystemCallFilter allows it")
	}
	// what keeps the clock from being set instead
	for _, c := range u["CapabilityBoundingSet"] {
		if c == "CAP_SYS_TIME" || c == "CAP_WAKE_ALARM" || strings.HasPrefix(c, "~") {
			t.Errorf("CapabilityBoundingSet %q: the clock must stay out of reach", c)
		}
	}
	if !has(u["NoNewPrivileges"], "yes") {
		t.Error("NoNewPrivileges=yes is what keeps CAP_SYS_TIME from coming back")
	}
	for _, c := range []string{"settimeofday", "clock_settime", "clock_adjtime", "@clock"} {
		if has(u["SystemCallFilter"], c) {
			t.Errorf("SystemCallFilter allows %s", c)
		}
	}
}

// A call outside the list must fail, not kill: a killed daemon restarts
// into the same call for ever and leaves no socket to change the setting.
func TestUnitRefusesInsteadOfKilling(t *testing.T) {
	u := unit(t)
	if got := u["SystemCallErrorNumber"]; len(got) != 1 || got[0] != "EPERM" {
		t.Errorf("SystemCallErrorNumber = %v, want EPERM", got)
	}
	if !has(u["SystemCallFilter"], "@system-service") {
		t.Errorf("SystemCallFilter is no longer the allow-list the checks here assume: %v", u["SystemCallFilter"])
	}
	for _, c := range u["SystemCallFilter"] {
		if strings.HasPrefix(c, "~") {
			t.Errorf("SystemCallFilter %q: a deny-list entry, the checks here assume an allow-list", c)
		}
	}
}
