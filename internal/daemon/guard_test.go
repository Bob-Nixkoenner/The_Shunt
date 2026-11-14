package daemon

import (
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/Bob-Nixkoenner/the_shunt/internal/engine"
	"github.com/Bob-Nixkoenner/the_shunt/internal/socks"
)

func guardPlan(t *testing.T) (*config.Config, *engine.Plan) {
	t.Helper()
	c, err := config.Parse(`
[daemon]
default_route = "tunnel:vps"
[tunnel.vps]
config = "vps.conf"
socks = "127.0.0.1:1080"
socks_users = ["1000", "someone"]
[tunnel.home]
config = "home.conf"
socks = "[::1]:1081"
`)
	if err != nil {
		t.Fatal(err)
	}
	all := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	p, err := engine.Compile(c, "shunt", map[string]engine.TunnelInfo{
		"vps":  {Iface: "sh-vps", HasV4: true, AllowedIPs: all, Addrs: []netip.Addr{netip.MustParseAddr("10.166.0.12")}},
		"home": {Iface: "sh-home", HasV4: true, AllowedIPs: all, Addrs: []netip.Addr{netip.MustParseAddr("10.9.0.2")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return c, p
}

// M-06: only running exits get a guard; socks_users resolve to UIDs, and a
// name that does not resolve is left out (closed to it), never ignored.
func TestExitUsers(t *testing.T) {
	c, _ := guardPlan(t)
	old := lookupUID
	defer func() { lookupUID = old }()
	lookupUID = func(name string) (uint32, error) {
		if name == "1000" {
			return 1000, nil
		}
		return 0, errors.New("unknown user")
	}
	d := &Daemon{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	got := d.exitUsers(c, map[string]string{"vps": socks.StateListening, "home": socks.StateTaken})
	if len(got) != 1 {
		t.Fatalf("exits %+v, want only the running one", got)
	}
	e := got[0]
	if e.Addr != netip.MustParseAddrPort("127.0.0.1:1080") || !e.Users || !slices.Equal(e.UIDs, []uint32{1000}) {
		t.Fatalf("exit %+v", e)
	}
	got = d.exitUsers(c, map[string]string{"home": socks.StateListening})
	if len(got) != 1 || got[0].Users {
		t.Fatalf("exit without socks_users: %+v", got)
	}
}
