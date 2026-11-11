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

func TestDefenseReputationSources(t *testing.T) {
	c := &Config{Defense: &defense.Config{ReputationSources: []string{"sslbl_ja3", "et_compromised"}}}
	if err := c.validateDefense(); err != nil {
		t.Fatal(err)
	}
	c.Defense.ReputationSources = []string{"nope"}
	if c.validateDefense() == nil {
		t.Fatal("unknown source accepted")
	}
}

func TestDefenseReputationOff(t *testing.T) {
	c := &Config{Defense: &defense.Config{ReputationOff: []string{"feodo"}}}
	if err := c.validateDefense(); err != nil {
		t.Fatal(err)
	}
	c.Defense.ReputationOff = []string{"et_compromised"}
	if c.validateDefense() == nil {
		t.Fatal("only built-in lists can be switched off")
	}
	c.Defense.ReputationSources = []string{"spamhaus_drop"}
	c.Defense.ReputationOff = nil
	if c.validateDefense() == nil {
		t.Fatal("spamhaus_drop must be refused")
	}
}
