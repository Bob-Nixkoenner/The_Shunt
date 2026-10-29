package desktopapp

import (
	"testing"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/api"
)

func TestTorHold(t *testing.T) {
	boot := 20
	st := &api.Status{Tunnels: []api.TunnelStatus{{Name: "tor1", Up: true, Bootstrap: &boot}, {Name: "wg", Up: false}}}
	v := View{Down: map[string]bool{"tor1": true, "wg": true}}
	var h TorHold
	now := time.Now()
	if f := h.Filter(v, st, now, TorNotifyAfter); f.Down["tor1"] || !f.Down["wg"] {
		t.Errorf("young tor tunnel must be hidden, wireguard not: %v", f.Down)
	}
	if !v.Down["tor1"] {
		t.Error("input view changed")
	}
	if f := h.Filter(v, st, now.Add(31*time.Second), TorNotifyAfter); !f.Down["tor1"] {
		t.Errorf("after 30 s it is shown: %v", f.Down)
	}
	v2 := View{Down: map[string]bool{"wg": true}}
	h.Filter(v2, st, now.Add(40*time.Second), TorNotifyAfter)
	if f := h.Filter(v, st, now.Add(41*time.Second), TorNotifyAfter); f.Down["tor1"] {
		t.Errorf("timer restarts after it was up: %v", f.Down)
	}
}
