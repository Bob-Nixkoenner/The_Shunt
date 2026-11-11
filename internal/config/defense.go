package config

import (
	"fmt"
	"net/netip"

	"github.com/Bob-Nixkoenner/the_shunt/internal/defense"
)

// DefenseConfig returns the [defense] section; absent means off (the zero
// value of defense.Config has Enabled false).
func (c *Config) DefenseConfig() defense.Config {
	if c.Defense == nil {
		d := defense.DefaultConfig()
		return d
	}
	d := *c.Defense
	if d.Features == nil {
		d.Features = defense.DefaultConfig().Features
	}
	if d.DecoyPorts == nil {
		d.DecoyPorts = defense.DefaultConfig().DecoyPorts
	}
	if d.BanSeconds <= 0 {
		d.BanSeconds = 3600
	}
	return d
}

func (c *Config) validateDefense() error {
	d := c.Defense
	if d == nil {
		return nil
	}
	known := map[string]bool{}
	for _, n := range defense.AllFeatures {
		known[n] = true
	}
	for n := range d.Features {
		if !known[n] {
			return fmt.Errorf("defense.features: unknown feature %q", n)
		}
	}
	seen := map[int]bool{}
	for _, p := range d.DecoyPorts {
		if p < 1 || p > 65535 {
			return fmt.Errorf("defense.decoy_ports: port %d out of range", p)
		}
		if seen[p] {
			return fmt.Errorf("defense.decoy_ports: port %d twice", p)
		}
		seen[p] = true
	}
	if d.BanSeconds < 0 || d.BanSeconds > 30*24*3600 {
		return fmt.Errorf("defense.ban_seconds %d (0 = default, at most 30 days)", d.BanSeconds)
	}
	okSrc := map[string]bool{}
	for _, n := range defense.OptionalSourceNames() {
		okSrc[n] = true
	}
	for _, n := range d.ReputationSources {
		if !okSrc[n] {
			return fmt.Errorf("defense.reputation_sources: unknown source %q (known: %v)", n, defense.OptionalSourceNames())
		}
	}
	for _, s := range d.Never {
		if _, err := netip.ParsePrefix(s); err != nil {
			if _, err2 := netip.ParseAddr(s); err2 != nil {
				return fmt.Errorf("defense.never: %q is no address or CIDR", s)
			}
		}
	}
	return nil
}
