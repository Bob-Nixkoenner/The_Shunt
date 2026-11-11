package config

import (
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/defense"
)

func TestDefenseDHCPProbe(t *testing.T) {
	c := &Config{Defense: &defense.Config{Enabled: true}}
	if got := c.DefenseConfig().DHCPProbe; got != defense.ProbeAuto {
		t.Errorf("default %q", got)
	}
	c.Defense.DHCPProbe = "off"
	if got := c.DefenseConfig().DHCPProbe; got != "off" {
		t.Errorf("kept %q", got)
	}
	if err := c.validateDefense(); err != nil {
		t.Error(err)
	}
	c.Defense.DHCPProbe = "maybe"
	if c.validateDefense() == nil {
		t.Error("bad value accepted")
	}
}
