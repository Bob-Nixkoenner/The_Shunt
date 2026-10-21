package config

import (
	"fmt"
	"github.com/Bob-Nixkoenner/the_shunt/dnslists"
	"net/url"
	"path/filepath"
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

// HageziPrefix starts the short name of a list of HaGeZi's DNS blocklists
// (https://github.com/hagezi/dns-blocklists, GPL-3.0; downloaded when used,
// not part of this program): "hagezi:pro" is adblock/pro.txt there. The
// adblock format is used because "||name^" also covers the subdomains.
const HageziPrefix = "hagezi:"

const hageziBase = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/"

var hageziNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,59}$`)

// DNSFilter blocks names from blocklists inside the DNS proxy: a blocked
// query never reaches any DNS server. Lists are only downloaded while a
// level that contains them is in use somewhere in the config.
type DNSFilter struct {
	// Default level for everything without its own (off | low | normal |
	// paranoid). Empty = normal.
	Default string `toml:"default,omitempty" json:"default,omitempty"`
	// Lists per level: a file name from Source ("malware"), a HaGeZi list
	// ("hagezi:pro") or an https URL.
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
	d, err := dnslists.Load()
	if err != nil { // the built-in file is checked by a test
		panic("dnslists/defaults.toml: " + err.Error())
	}
	return DNSFilter{
		Default:  levelName(d.DefaultLevel),
		Low:      d.For(1, goos),
		Normal:   d.For(2, goos),
		Paranoid: d.For(3, goos),
	}
}

// levelName maps 0-3 to off/low/normal/paranoid.
func levelName(n int) string {
	return []string{FilterOff, FilterLow, FilterNormal, FilterParanoid}[n]
}

// Filter returns the DNS filter settings in effect (defaults filled in).
func (c *Config) Filter() DNSFilter {
	if c.DNSFilter == nil {
		return DefaultDNSFilter()
	}
	f := *c.DNSFilter
	if f.Low == nil && f.Normal == nil && f.Paranoid == nil {
		// only default/allow set: the built-in lists apply
		def := DefaultDNSFilter()
		f.Low, f.Normal, f.Paranoid = def.Low, def.Normal, def.Paranoid
		if f.Default == "" {
			f.Default = def.Default
		}
	}
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
	var out []string
	seen := map[string]bool{}
	for _, l := range own {
		for _, name := range l {
			if k := f.listKey(name); !seen[k] { // "easylist" and its full URL are one list
				seen[k] = true
				out = append(out, name)
			}
		}
	}
	return out
}

// listKey identifies a list by where it comes from.
func (f DNSFilter) listKey(name string) string {
	return strings.ToLower(strings.TrimSuffix(f.ListURL(name), "/"))
}

// Tidy removes the redundant entries Duplicates reports: a list stays in the
// lowest level that has it. Order is kept.
func (f DNSFilter) Tidy() DNSFilter {
	seen := map[string]bool{}
	keep := func(in []string) []string {
		out := []string{}
		for _, name := range in {
			if k := f.listKey(name); !seen[k] {
				seen[k] = true
				out = append(out, name)
			}
		}
		return out
	}
	f.Low, f.Normal, f.Paranoid = keep(f.Low), keep(f.Normal), keep(f.Paranoid)
	allow := map[string]bool{}
	var al []string
	for _, name := range f.AllowLists {
		if k := f.listKey(name); !allow[k] {
			allow[k] = true
			al = append(al, name)
		}
	}
	f.AllowLists = al
	return f
}

// Duplicates describes lists that are listed twice: in one level, or again in
// a higher level that already includes the lower one (levels build on each
// other, so the second entry does nothing). Allowlists count too.
func (f DNSFilter) Duplicates() []string {
	var out []string
	seen := map[string]string{}
	for _, lv := range []struct {
		name  string
		lists []string
	}{{FilterLow, f.Low}, {FilterNormal, f.Normal}, {FilterParanoid, f.Paranoid}} {
		for _, name := range lv.lists {
			k := f.listKey(name)
			if first, ok := seen[k]; ok {
				if first == lv.name {
					out = append(out, fmt.Sprintf("dns_filter.%s lists %s twice", lv.name, name))
				} else {
					out = append(out, fmt.Sprintf("dns_filter.%s: %s is already in %s, which it includes", lv.name, name, first))
				}
				continue
			}
			seen[k] = lv.name
		}
	}
	allow := map[string]bool{}
	for _, name := range f.AllowLists {
		k := f.listKey(name)
		if allow[k] {
			out = append(out, fmt.Sprintf("dns_filter.allow_lists lists %s twice", name))
		}
		allow[k] = true
	}
	return out
}

// ListURL returns where a list comes from.
func (f DNSFilter) ListURL(name string) string {
	if file, ok := strings.CutPrefix(name, HageziPrefix); ok {
		return hageziBase + file + ".txt"
	}
	if strings.HasPrefix(name, "https://") || IsLocalList(name) {
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

// IsLocalList: "file:/etc/lists/mine.txt" (Windows: "file:C:\lists\mine.txt") is
// a list on this machine instead of a download.
func IsLocalList(ref string) bool { return strings.HasPrefix(ref, "file:") }

// LocalListPath returns the path of a local list reference.
func LocalListPath(ref string) string { return strings.TrimPrefix(ref, "file:") }

func validListRef(where, l string) error {
	if IsLocalList(l) {
		p := LocalListPath(l)
		if !filepath.IsAbs(p) || strings.Contains(p, "..") {
			return fmt.Errorf("%s: %q: a local list needs an absolute path (file:/path/to/list.txt)", where, l)
		}
		return nil
	}
	if strings.HasPrefix(l, "https://") {
		if u, err := url.Parse(l); err != nil || u.Host == "" {
			return fmt.Errorf("%s: invalid URL %q", where, l)
		}
		return nil
	}
	if file, ok := strings.CutPrefix(l, HageziPrefix); ok {
		if !hageziNameRe.MatchString(file) || strings.Contains(file, "..") {
			return fmt.Errorf("%s: %q is not a HaGeZi list name (hagezi:pro, hagezi:tif.mini, ...)", where, l)
		}
		return nil
	}
	if !listNameRe.MatchString(l) || strings.Contains(l, "..") {
		return fmt.Errorf("%s: %q is neither a list name nor an https:// URL", where, l)
	}
	return nil
}
