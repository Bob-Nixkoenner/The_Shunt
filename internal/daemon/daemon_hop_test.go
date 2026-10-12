package daemon

import (
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/Bob-Nixkoenner/the_shunt/internal/wgconf"
)

func TestHopMTU(t *testing.T) {
	c, err := config.Parse("[tunnel.a]\nconfig=\"a\"\n[tunnel.b]\nconfig=\"b\"\nvia=\"a\"\n[tunnel.c]\nconfig=\"c\"\nvia=\"tunnel:b\"\n[tunnel.o]\nconfig=\"o\"\ndriver=\"openvpn\"\n[tunnel.d]\nconfig=\"d\"\nvia=\"o\"\n")
	if err != nil {
		t.Fatal(err)
	}
	p := &Prepared{Config: c, Confs: map[string]*wgconf.Config{"a": {}, "b": {}, "c": {}, "d": {}}}
	for name, want := range map[string]int{"a": 0, "b": 1340, "c": 1260, "d": 1420} {
		if got := hopConf(p, name).MTU; got != want {
			t.Errorf("%s: mtu %d, want %d", name, got, want)
		}
	}
	p.Confs["b"].MTU = 1300
	if got := hopConf(p, "b").MTU; got != 1300 {
		t.Errorf("explicit MTU replaced: %d", got)
	}
	if p.Confs["b"] == hopConf(p, "c") {
		t.Error("shared config modified")
	}
}
