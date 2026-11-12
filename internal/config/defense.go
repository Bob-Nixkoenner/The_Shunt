package config

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/Bob-Nixkoenner/the_shunt/internal/defense"
)

// DefenseConfig returns the [defense] section; absent means off (the zero
// value of defense.Config has Enabled false).
func (c *Config) DefenseConfig() defense.Config {
	if c.Defense == nil {
		return defense.DefaultConfig()
	}
	d := *c.Defense
	// Features the file does not mention keep their default (watch on, block
	// off): a partial [defense.features.*] table must not silently switch
	// the other sensors (ARP, DHCP, DNS, brute force ...) off.
	f := defense.DefaultConfig().Features
	for k, v := range d.Features {
		f[k] = v
	}
	d.Features = f
	if d.DecoyPorts == nil {
		d.DecoyPorts = defense.DefaultConfig().DecoyPorts
	}
	if d.BanSeconds <= 0 {
		d.BanSeconds = 3600
	}
	if d.BanSeconds2 == 0 {
		d.BanSeconds2 = defense.DefaultBanSeconds2
	}
	if d.BanSeconds3 == 0 {
		d.BanSeconds3 = defense.BanForever
	}
	if d.DHCPProbe == "" {
		d.DHCPProbe = defense.ProbeAuto
	}
	if d.DNSProbe == "" {
		d.DNSProbe = defense.ProbeAuto
	}
	d.Evidence = d.Evidence.Normalized()
	return d
}

func (c *Config) validateDefense() error {
	d := c.Defense
	if d == nil {
		return nil
	}
	if !defense.ValidProbeMode(d.DHCPProbe) {
		return fmt.Errorf("defense.dhcp_probe %q (auto, on or off)", d.DHCPProbe)
	}
	if !defense.ValidProbeMode(d.DNSProbe) {
		return fmt.Errorf("defense.dns_probe %q (auto, on or off)", d.DNSProbe)
	}
	if err := defense.ValidateOutsideScan(d.OutsideScan); err != nil {
		return err
	}
	if err := defense.ValidateEvidence(d.Evidence); err != nil {
		return err
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
	for i, v := range []int{d.BanSeconds2, d.BanSeconds3} {
		if v < -1 || v > 30*24*3600 {
			return fmt.Errorf("defense.ban_seconds_%d %d (-1 = until lifted by hand, 0 = default, at most 30 days)", i+2, v)
		}
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
	okOff := map[string]bool{}
	for _, n := range defense.BuiltinSourceNames() {
		okOff[n] = true
	}
	for _, n := range d.ReputationOff {
		if !okOff[n] {
			return fmt.Errorf("defense.reputation_off: unknown source %q (known: %v)", n, defense.BuiltinSourceNames())
		}
	}
	if len(d.TLSTargets) > defense.MaxTLSTargets {
		return fmt.Errorf("defense.tls_targets: at most %d", defense.MaxTLSTargets)
	}
	for _, h := range d.TLSTargets {
		if !validTLSHost(h) {
			return fmt.Errorf("defense.tls_targets: %q is no host name (no scheme, port or address)", h)
		}
	}
	if len(d.RebindAllow) > 64 {
		return fmt.Errorf("defense.rebind_allow: at most 64 entries")
	}
	for _, h := range d.RebindAllow {
		if !validTLSHost(h) {
			return fmt.Errorf("defense.rebind_allow: %q is no domain name (no scheme, port or address)", h)
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

// validTLSHost: a plain DNS host name with at least two labels (letters,
// digits, hyphens), no address, scheme, port or path.
func validTLSHost(h string) bool {
	if len(h) < 4 || len(h) > 253 || !strings.Contains(h, ".") {
		return false
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return false
	}
	for _, l := range strings.Split(h, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, r := range l {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}
