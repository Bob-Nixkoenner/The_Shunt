package config

import (
	"fmt"
	"net/url"
	"regexp"
	"runtime"
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
	// A level includes the lists of the one below (low < normal < paranoid).
	Low      []string `toml:"low" json:"low"`
	Normal   []string `toml:"normal" json:"normal"`
	Paranoid []string `toml:"paranoid" json:"paranoid"`
	// Allow: names (and their subdomains) that are never blocked.
	Allow []string `toml:"allow,omitempty" json:"allow,omitempty"`
	// AllowLists: lists of names that are never blocked (a list name from
	// Source or an https URL; hosts, plain names, ||name^ or @@||name^).
	AllowLists []string `toml:"allow_lists,omitempty" json:"allow_lists,omitempty"`
	// Source: base URL for list names. Empty = DefaultFilterSource.
	Source string `toml:"source,omitempty" json:"source,omitempty"`
}

// DefaultDNSFilter is in effect while the config has no [dns_filter]. It is
// what the maintainer's own machines settled on (Linux host, Windows VM),
// minus the lists that have nothing to do with this OS: Windows' telemetry
// lists are in "normal" on Windows and nowhere else, the phone and TV lists
// (Samsung, LG) are not in any default. Android gets its own set in the app.
func DefaultDNSFilter() DNSFilter {
	return defaultDNSFilterFor(runtime.GOOS)
}

func defaultDNSFilterFor(goos string) DNSFilter {
	normal := []string{"notserious", "Fake-Science", "spam.mails", "crypto"}
	if goos == "windows" {
		normal = append(normal, "Win10Telemetry", "MS-Office-Telemetry")
	}
	return DNSFilter{
		Default: FilterNormal,
		Low:     []string{"easylist", "Phishing-Angriffe", "malware", "Corona-Blocklist", "SupportingRussia"},
		Normal:  normal,
		Paranoid: []string{
			"gambling", "Streaming", "DatingSites", "child-protection", "proxies",
			"DomainSquatting1", "DomainSquatting2", "DomainSquatting3", "DomainSquatting4",
			"pornblock1", "pornblock2", "pornblock3", "pornblock4", "pornblock5", "pornblock6", "Overblock",
		},
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

// Lists returns the lists of a level (nil for off). Levels build on each
// other: normal also has everything of low, paranoid everything of normal.
func (f DNSFilter) Lists(level string) []string {
	var own [][]string
	switch level {
	case FilterLow:
		own = [][]string{f.Low}
	case FilterNormal:
		own = [][]string{f.Low, f.Normal}
	case FilterParanoid:
		own = [][]string{f.Low, f.Normal, f.Paranoid}
	default:
		return nil
	}
	if len(own) == 1 {
		return own[0]
	}
	var out []string
	seen := map[string]bool{}
	for _, l := range own {
		for _, name := range l {
			if !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	return out
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
			if err := validListRef("dns_filter."+lvl, l); err != nil {
				return err
			}
		}
	}
	for _, l := range f.AllowLists {
		if err := validListRef("dns_filter.allow_lists", l); err != nil {
			return err
		}
	}
	for _, a := range f.Allow {
		if NormalizeDomain(a) == "" {
			return fmt.Errorf("dns_filter.allow: invalid name %q", a)
		}
	}
	return nil
}

func validListRef(where, l string) error {
	if strings.HasPrefix(l, "https://") {
		if u, err := url.Parse(l); err != nil || u.Host == "" {
			return fmt.Errorf("%s: invalid URL %q", where, l)
		}
		return nil
	}
	if !listNameRe.MatchString(l) || strings.Contains(l, "..") {
		return fmt.Errorf("%s: %q is neither a list name nor an https:// URL", where, l)
	}
	return nil
}
