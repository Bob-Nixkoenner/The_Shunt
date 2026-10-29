package winsvc

import (
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
)

func TestInboundFor(t *testing.T) {
	c, err := config.Parse(`
[daemon]
default_route = "direct"
[inbound]
enabled = true
allow = ["tcp/1716", "udp/1716"]
[[network]]
name = "home"
ssid = ["Home"]
default_route = "direct"
inbound = "lan"
[[network]]
name = "work"
ssid = ["Work"]
default_route = "direct"
inbound = "open"
`)
	if err != nil {
		t.Fatal(err)
	}
	if a := InboundFor(c, ""); !a.On || a.LAN {
		t.Errorf("unknown network must be closed: %+v", a)
	}
	if a := InboundFor(c, "home"); !a.On || !a.LAN || len(a.Ports) != 2 {
		t.Errorf("home: %+v", a)
	}
	if a := InboundFor(c, "work"); a.On {
		t.Errorf("open means no filters: %+v", a)
	}
	c.Inbound.Enabled = false
	if a := InboundFor(c, ""); a.On {
		t.Errorf("disabled: %+v", a)
	}
}
