package config

import (
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/defense"
)

func TestDefenseConfigPartialFeaturesKeepDefaults(t *testing.T) {
	c := &Config{Defense: &defense.Config{Enabled: true, Features: map[string]defense.Feature{
		"scan":  {Watch: true, Block: true},
		"decoy": {Watch: false},
	}}}
	f := c.DefenseConfig().Features
	for _, n := range []string{defense.FeatARP, defense.FeatDHCP, defense.FeatDNS, defense.FeatBrute} {
		if !f[n].Watch || f[n].Block {
			t.Fatalf("%s should default to watch on, block off: %+v", n, f[n])
		}
	}
	if !f["scan"].Block || f["decoy"].Watch {
		t.Fatalf("explicit entries must win: %+v %+v", f["scan"], f["decoy"])
	}
}

func TestDefenseNewFeaturesDefaultAndRebindAllow(t *testing.T) {
	c := &Config{Defense: &defense.Config{Enabled: true, Features: map[string]defense.Feature{"scan": {Watch: true}}}}
	f := c.DefenseConfig().Features
	for _, n := range []string{defense.FeatDHCPOption, defense.FeatRogueRA, defense.FeatDNSRebind, defense.FeatNewIface} {
		if !f[n].Watch || f[n].Block {
			t.Fatalf("%s should default to watch on, block off: %+v", n, f[n])
		}
	}
	if c.DefenseConfig().RebindProtect {
		t.Fatal("rebind_protect must default to off")
	}
	c.Defense.RebindAllow = []string{"home.example.org"}
	if err := c.validateDefense(); err != nil {
		t.Fatal(err)
	}
	c.Defense.RebindAllow = []string{"https://x.example"}
	if err := c.validateDefense(); err == nil {
		t.Fatal("scheme must be refused")
	}
}
