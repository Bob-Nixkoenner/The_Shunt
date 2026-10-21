// Package dnslists holds the default DNS filter lists (defaults.toml, built
// in with go:embed) and renders them as docs/DNS-LISTS.md.
package dnslists

import (
	_ "embed"
	"fmt"
	"strings"

	"github.com/BurntSushi/toml"
)

//go:embed defaults.toml
var defaultsTOML []byte

// Entry is one default list.
type Entry struct {
	Name  string   `toml:"name"`
	URL   string   `toml:"url"`
	Level int      `toml:"level"`
	OS    []string `toml:"os"`
	About string   `toml:"about"`
}

// Defaults is the parsed defaults.toml.
type Defaults struct {
	DefaultLevel int     `toml:"default_level"`
	Lists        []Entry `toml:"list"`
}

// Load parses the built-in defaults.
func Load() (Defaults, error) { return parse(defaultsTOML) }

func parse(b []byte) (Defaults, error) {
	var d Defaults
	md, err := toml.Decode(string(b), &d)
	if err != nil {
		return d, err
	}
	if u := md.Undecoded(); len(u) > 0 {
		return d, fmt.Errorf("unknown keys: %v", u)
	}
	if d.DefaultLevel < 0 || d.DefaultLevel > 3 {
		return d, fmt.Errorf("default_level %d (0-3)", d.DefaultLevel)
	}
	for _, e := range d.Lists {
		if e.Level < 1 || e.Level > 3 {
			return d, fmt.Errorf("list %q: level %d (1-3)", e.Name, e.Level)
		}
		if e.Name == "" {
			return d, fmt.Errorf("list without name")
		}
	}
	return d, nil
}

// Ref is what the config stores for the list: its URL or its RPiList name.
func (e Entry) Ref() string {
	if e.URL != "" {
		return e.URL
	}
	return e.Name
}

// For returns the lists of one level (1-3) that apply on goos.
func (d Defaults) For(level int, goos string) []string {
	var out []string
	for _, e := range d.Lists {
		if e.Level != level {
			continue
		}
		if len(e.OS) > 0 && !contains(e.OS, goos) {
			continue
		}
		out = append(out, e.Ref())
	}
	return out
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// Markdown renders the page people can read and comment on.
func Markdown(d Defaults) string {
	names := map[int]string{1: "Low", 2: "Normal", 3: "Paranoid"}
	var b strings.Builder
	b.WriteString("<!-- generated from dnslists/defaults.toml - do not edit; run: go test ./dnslists -update -->\n")
	b.WriteString("# Default DNS filter lists\n\n")
	b.WriteString("These are the blocklists The Shunt uses out of the box. The levels build on each other:\n")
	b.WriteString("**Normal** = Low + its own lists, **Paranoid** = Normal + its own lists.\n")
	fmt.Fprintf(&b, "Default level: **%s** (%d).\n\n", names[d.DefaultLevel], d.DefaultLevel)
	b.WriteString("**Something missing, too much, or in the wrong level?** Open an issue or a pull request that edits\n")
	b.WriteString("[`dnslists/defaults.toml`](../dnslists/defaults.toml) – this page is generated from it.\n")
	b.WriteString("Lists come from [RPiList/specials](https://github.com/RPiList/specials/tree/master/Blocklisten) and from\n")
	b.WriteString("[HaGeZi's DNS blocklists](https://github.com/hagezi/dns-blocklists) (GPL-3.0; the `hagezi:` ones) - many thanks to both projects.\n")
	b.WriteString("They are downloaded when used and are not part of The Shunt. HaGeZi's Light, Pro and Pro++ build on each other (each\n")
	b.WriteString("contains the one before); the levels still use a bigger one each, which keeps Low small and costs only a little overlap.\n")
	for lv := 1; lv <= 3; lv++ {
		fmt.Fprintf(&b, "\n## Level %d – %s\n\n| List | What it blocks | Only on |\n|---|---|---|\n", lv, names[lv])
		for _, e := range d.Lists {
			if e.Level != lv {
				continue
			}
			name := "`" + e.Name + "`"
			if e.URL != "" {
				name = "[" + e.Name + "](" + e.URL + ")"
			} else if strings.HasPrefix(e.Name, "hagezi:") {
				name = "[" + e.Name + "](https://github.com/hagezi/dns-blocklists)"
			}
			fmt.Fprintf(&b, "| %s | %s | %s |\n", name, e.About, strings.Join(e.OS, ", "))
		}
	}
	return b.String()
}
