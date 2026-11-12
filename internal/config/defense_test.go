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

func TestDefenseTLSTargets(t *testing.T) {
	c := &Config{Defense: &defense.Config{TLSTargets: []string{"www.example.org", "api.example.net"}}}
	if err := c.validateDefense(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"https://example.org", "example.org:443", "192.0.2.1", "localhost", "a b.example", "ex/ample.org", "-x.example.org"} {
		c.Defense.TLSTargets = []string{bad}
		if c.validateDefense() == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	c.Defense.TLSTargets = make([]string, defense.MaxTLSTargets+1)
	for i := range c.Defense.TLSTargets {
		c.Defense.TLSTargets[i] = "a.example.org"
	}
	if c.validateDefense() == nil {
		t.Fatal("too many targets accepted")
	}
}

func TestDefenseBanStepsDefaultsAndLimits(t *testing.T) {
	c := &Config{Defense: &defense.Config{Enabled: true, BanSeconds: 300}}
	d := c.DefenseConfig()
	if d.BanSeconds2 != 86400 || d.BanSeconds3 != defense.BanForever {
		t.Fatalf("%+v", d)
	}
	for _, v := range []int{-2, 31 * 24 * 3600} {
		bad := &Config{Defense: &defense.Config{BanSeconds2: v}}
		if bad.validateDefense() == nil {
			t.Fatalf("ban_seconds_2 %d accepted", v)
		}
	}
	ok := &Config{Defense: &defense.Config{BanSeconds2: -1, BanSeconds3: -1}}
	if err := ok.validateDefense(); err != nil {
		t.Fatal(err)
	}
}
