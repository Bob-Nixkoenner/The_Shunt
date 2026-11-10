package tunnel

import (
	"strings"
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/tsconf"
)

// The auth key never appears on the command line.
func TestTailscaleKeyNotInArgs(t *testing.T) {
	ts := &Tailscale{spec: TailscaleSpec{Conf: &tsconf.Config{AuthKey: "tskey-auth-secret"}}}
	args := strings.Join(ts.upArgs("/state/authkey"), " ")
	if strings.Contains(args, "tskey-auth-secret") || !strings.Contains(args, "--auth-key=file:/state/authkey") {
		t.Fatalf("args: %s", args)
	}
}
