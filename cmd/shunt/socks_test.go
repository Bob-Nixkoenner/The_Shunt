package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/api"
	"github.com/Bob-Nixkoenner/the_shunt/internal/i18n"
)

// M-04: an exit whose address another program holds is shown as blocked,
// never as up, even while its tunnel is up.
func TestSocksListShowsTakenExit(t *testing.T) {
	i18n.Set("en")
	defer i18n.Set(i18n.Detect())
	st := api.Status{Tunnels: []api.TunnelStatus{
		{Name: "a", Up: true, Socks: "127.0.0.1:1080", SocksState: "taken"},
		{Name: "b", Up: true, Socks: "127.0.0.1:1081", SocksState: "listening"},
		{Name: "c", Up: false, Socks: "127.0.0.1:1082", SocksState: "listening"},
		{Name: "d", Up: true, Socks: "127.0.0.1:1083", SocksState: "failed"},
		{Name: "e", Up: true, Socks: "127.0.0.1:1084"}, // older daemon
		{Name: "f", Disabled: true, Socks: "127.0.0.1:1085"},
	}}
	var b bytes.Buffer
	if err := writeSocks(&b, st); err != nil {
		t.Fatal(err)
	}
	lines := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(b.String()), "\n") {
		f := strings.Fields(l)
		lines[strings.TrimPrefix(f[0], "tunnel:")] = strings.Join(f[2:], " ")
	}
	for name, want := range map[string]string{"a": "BLOCKED", "b": "up", "c": "tunnel down", "d": "not listening", "e": "up", "f": "tunnel switched off"} {
		if !strings.HasPrefix(lines[name], want) {
			t.Errorf("exit %s: %q, want %q…", name, lines[name], want)
		}
	}
	if strings.Contains(lines["a"], "up") && !strings.Contains(lines["a"], "BLOCKED") {
		t.Errorf("taken exit shown as up: %q", lines["a"])
	}
}
