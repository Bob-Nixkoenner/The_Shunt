package config

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// DNS filter levels. A level is a set of blocklists; which level applies to a
// query depends on where it comes from (rule > tunnel/network > default).
const (
	FilterOff      = "off"
	FilterLow      = "low"
	FilterNormal   = "normal"
	FilterParanoid = "paranoid"
)

// FilterLevels in order, without off.
var FilterLevels = []string{FilterLow, FilterNormal, FilterParanoid}

// DefaultFilterSource: the lists of RPiList (https://github.com/RPiList/specials),
// referenced by file name.
const DefaultFilterSource = "https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/"

// DNSFilter blocks names from blocklists inside the DNS proxy: a blocked
// query never reaches any DNS server. Lists are only downloaded while a
// level that contains them is in use somewhere in the config.
type DNSFilter struct {
	// Default level for everything without its own (off | low | normal |
	// paranoid). Empty = normal.
	Default string `toml:"default,omitempty" json:"default,omitempty"`
	// Lists per level: a file name from Source ("easylist") or an https URL.
	Low      []string `toml:"low" json:"low"`
	Normal   []string `toml:"normal" json:"normal"`
	Paranoid []string `toml:"paranoid" json:"paranoid"`
	// Allow: names (and their subdomains) that are never blocked.
	Allow []string `toml:"allow,omitempty" json:"allow,omitempty"`
	// Source: base URL for list names. Empty = DefaultFilterSource.
	Source string `toml:"source,omitempty" json:"source,omitempty"`
}

// DefaultDNSFilter is in effect while the config has no [dns_filter].
func DefaultDNSFilter() DNSFilter {
	return DNSFilter{
		Default:  FilterNormal,
		Low:      []string{},
		Normal:   []string{"easylist"},
		Paranoid: []string{"easylist", "Phishing-Angriffe", "malware", "Win10Telemetry", "MS-Office-Telemetry", "crypto"},
	}
}

// Filter returns the DNS filter settings in effect (defaults filled in).
func (c *Config) Filter() DNSFilter {
	if c.DNSFilter == nil {
		return DefaultDNSFilter()
	}
	f := *c.DNSFilter
	if f.Default == "" {
		f.Default = FilterNormal
	}
	return f
}

// Lists returns the lists of a level (nil for off).
func (f DNSFilter) Lists(level string) []string {
	switch level {
	case FilterLow:
		return f.Low
	case FilterNormal:
		return f.Normal
	case FilterParanoid:
		return f.Paranoid
	}
	return nil
}

// ListURL returns where a list comes from.
func (f DNSFilter) ListURL(name string) string {
	if strings.HasPrefix(name, "https://") {
		return name
	}
	src := f.Source
	if src == "" {
		src = DefaultFilterSource
	}
	return strings.TrimSuffix(src, "/") + "/" + url.PathEscape(name)
}

// UsedFilterLevels: the levels referenced anywhere in the config (default,
// tunnels, networks, rules). Only their lists are downloaded.
func (c *Config) UsedFilterLevels() []string {
	used := map[string]bool{c.Filter().Default: true}
	for _, t := range c.Tunnels {
		used[t.DNSFilter] = true
	}
	for _, n := range c.Networks {
		used[n.DNSFilter] = true
	}
	for _, r := range c.Rules {
		used[r.DNSFilter] = true
	}
	var out []string
	for _, l := range FilterLevels {
		if used[l] {
			out = append(out, l)
		}
	}
	return out
}

var listNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)

func validFilterLevel(l string, allowEmpty bool) bool {
	return (allowEmpty && l == "") || l == FilterOff || l == FilterLow || l == FilterNormal || l == FilterParanoid
}

func (c *Config) validateFilter() error {
	if c.DNSFilter == nil {
		return nil
	}
	f := c.DNSFilter
	if !validFilterLevel(f.Default, true) {
		return fmt.Errorf("dns_filter.default: %q (off | low | normal | paranoid)", f.Default)
	}
	if f.Source != "" && !strings.HasPrefix(f.Source, "https://") {
		return fmt.Errorf("dns_filter.source must be an https:// URL")
	}
	for _, lvl := range FilterLevels {
		for _, l := range f.Lists(lvl) {
			if strings.HasPrefix(l, "https://") {
				if u, err := url.Parse(l); err != nil || u.Host == "" {
					return fmt.Errorf("dns_filter.%s: invalid URL %q", lvl, l)
				}
				continue
			}
			if !listNameRe.MatchString(l) || strings.Contains(l, "..") {
				return fmt.Errorf("dns_filter.%s: %q is neither a list name nor an https:// URL", lvl, l)
			}
		}
	}
	for _, a := range f.Allow {
		if NormalizeDomain(a) == "" {
			return fmt.Errorf("dns_filter.allow: invalid name %q", a)
		}
	}
	return nil
}
