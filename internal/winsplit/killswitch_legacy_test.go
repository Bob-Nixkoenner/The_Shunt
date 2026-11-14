package winsplit

import (
	"errors"
	"strings"
	"testing"
)

// fakeNetsh answers "firewall delete rule" with success only for rules in
// present (netsh fails with "No rules match" otherwise) and records calls.
type fakeNetsh struct {
	present map[string]bool
	calls   []string
}

func (f *fakeNetsh) run(args ...string) error {
	c := strings.Join(args, " ")
	f.calls = append(f.calls, c)
	if len(args) == 4 && args[0] == "firewall" && args[1] == "delete" {
		name := strings.TrimPrefix(args[3], "name=")
		if !f.present[name] {
			return errors.New("No rules match the specified criteria.")
		}
		delete(f.present, name)
	}
	return nil
}

func (f *fakeNetsh) policySet() bool {
	for _, c := range f.calls {
		if strings.HasPrefix(c, "set allprofiles firewallpolicy") {
			return true
		}
	}
	return false
}

func TestLegacyCleanupKeepsUserPolicy(t *testing.T) {
	f := &fakeNetsh{present: map[string]bool{}}
	if legacyCleanupWith(f.run) {
		t.Error("found legacy rules on a clean machine")
	}
	if f.policySet() {
		t.Errorf("firewall policy reset without the old kill switch: %q", f.calls)
	}
}

func TestLegacyCleanupResetsOldKillSwitch(t *testing.T) {
	f := &fakeNetsh{present: map[string]bool{ksPrefix + "service": true, ksPrefix + "lan": true}}
	if !legacyCleanupWith(f.run) {
		t.Error("legacy rules not found")
	}
	if len(f.present) != 0 {
		t.Errorf("rules left: %v", f.present)
	}
	if !f.policySet() || f.calls[len(f.calls)-1] != "set allprofiles firewallpolicy blockinbound,allowoutbound" {
		t.Errorf("old block-outbound policy not lifted: %q", f.calls)
	}
	// the next call finds nothing and leaves the policy alone
	f.calls = nil
	if legacyCleanupWith(f.run) || f.policySet() {
		t.Errorf("second cleanup touched the policy: %q", f.calls)
	}
}
