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
	if a := InboundFor(c, "", nil); !a.On || a.LAN {
		t.Errorf("unknown network must be closed: %+v", a)
	}
	if a := InboundFor(c, "home", nil); !a.On || !a.LAN || len(a.Ports) != 2 {
		t.Errorf("home: %+v", a)
	}
	if a := InboundFor(c, "work", nil); a.On {
		t.Errorf("open means no filters: %+v", a)
	}
	c.Inbound.Enabled = false
	if a := InboundFor(c, "", nil); a.On {
		t.Errorf("disabled: %+v", a)
	}
	// decoys: let in in every mode; with the protection off only them
	if a := InboundFor(c, "", []int{2222, 22, 22, 0, 70000}); !a.On || !a.Open || len(a.Decoys) != 2 || a.Decoys[0] != 22 {
		t.Errorf("off + decoys: %+v", a)
	}
	c.Inbound.Enabled = true
	if a := InboundFor(c, "", []int{22}); !a.On || a.Open || len(a.Decoys) != 1 {
		t.Errorf("closed + decoys: %+v", a)
	}
	if a := InboundFor(c, "work", []int{22, 23}); !a.On || !a.Open || len(a.Decoys) != 2 {
		t.Errorf("open + decoys: %+v", a)
	}
	var many []int
	for p := 1000; p < 1200; p++ {
		many = append(many, p)
	}
	if a := InboundFor(c, "home", many); len(a.Decoys) != MaxDecoyPermits {
		t.Errorf("decoy cap: %d", len(a.Decoys))
	}
}
