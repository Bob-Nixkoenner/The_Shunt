package config

import (
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/defense"
	"github.com/Bob-Nixkoenner/the_shunt/internal/netdetect"
)

func TestNetClassAndDefenseValidation(t *testing.T) {
	c := &Config{Networks: []Network{{Name: "a", SSID: []string{"x"}, Class: "trusted"}, {Name: "b", SSID: []string{"y"}}}}
	if g := c.NetClass(netdetect.Info{SSID: "x"}); g != defense.ClassTrusted {
		t.Fatal(g)
	}
	if g := c.NetClass(netdetect.Info{SSID: "y"}); g != defense.ClassPublic {
		t.Fatal(g)
	}
	if g := c.NetClass(netdetect.Info{SSID: "zzz"}); g != defense.ClassPublic {
		t.Fatal(g)
	}
	if c.DefenseConfig().Enabled {
		t.Fatal("must default to off")
	}
	c.Defense = &defense.Config{DecoyPorts: []int{0}}
	if c.validateDefense() == nil {
		t.Fatal("bad port accepted")
	}
	c.Defense = &defense.Config{Never: []string{"192.0.2.0/24", "198.51.100.7"}, Features: map[string]defense.Feature{"scan": {Watch: true}}}
	if err := c.validateDefense(); err != nil {
		t.Fatal(err)
	}
	c.Defense.Features["nope"] = defense.Feature{}
	if c.validateDefense() == nil {
		t.Fatal("unknown feature accepted")
	}
}
