package main

import (
	"strings"
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/i18n"
)

// The help text is translated line by line: every explanation has a German one.
func TestUsageGerman(t *testing.T) {
	de := i18n.Dict("de")
	for _, e := range usageEntries {
		if e.desc != "" && de[e.desc] == "" {
			t.Errorf("no German for %q", e.desc)
		}
	}
	for _, k := range []string{"usage: shunt [-s socket] <command>", "commands:"} {
		if de[k] == "" {
			t.Errorf("no German for %q", k)
		}
	}
}

func TestUsageEnglishAndWrap(t *testing.T) {
	i18n.Set("en")
	u := usage()
	if !strings.HasPrefix(u, "usage: shunt") || !strings.Contains(u, "  status [--json]") {
		t.Errorf("unexpected usage:\n%s", u)
	}
	for _, l := range strings.Split(u, "\n") {
		if len([]rune(l)) > 84 {
			t.Errorf("line too long: %q", l)
		}
	}
}
