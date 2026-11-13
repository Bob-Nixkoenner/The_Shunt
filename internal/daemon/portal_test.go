package daemon

import (
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/captive"
	"github.com/Bob-Nixkoenner/the_shunt/internal/engine"
)

// During a login page only the login browser's group may be entered without
// the manage right; every other group still needs it.
func TestPortalException(t *testing.T) {
	for _, c := range []struct {
		state, group, to string
		want             bool
	}{
		{captive.Portal, engine.CaptiveGroup, "direct", true},
		{captive.Portal, "work", "direct", false},
		{captive.Portal, engine.CaptiveGroup, "tunnel:x", false},
		{captive.Online, engine.CaptiveGroup, "direct", false},
		{captive.Offline, "work", "direct", false},
	} {
		if got := portalException(c.state, c.group, c.to); got != c.want {
			t.Errorf("%+v: %v", c, got)
		}
	}
}
