// Package config loads and validates the shuntd configuration (TOML).
package config

import (
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

// DefaultPath is where shuntd looks for its config.
const DefaultPath = "/etc/shunt/shunt.toml"

// Config is the top level config file.
type Config struct {
	Daemon  Daemon            `toml:"daemon"`
	Tunnels map[string]Tunnel `toml:"tunnel"`
	Groups  map[string]Group  `toml:"group"`
	Rules   []Rule            `toml:"rule"`
}

// Daemon holds daemon wide settings.
type Daemon struct {
	Socket      string `toml:"socket"`
	SocketGroup string `toml:"socket_group"`
	// CgroupRoot is the cgroup (relative to the cgroup2 mount) shuntd owns.
	// Empty means: the cgroup shuntd was started in (systemd Delegate=yes).
	CgroupRoot   string `toml:"cgroup_root"`
	DefaultRoute string `toml:"default_route"`
}

// Tunnel references a wg-quick style file.
type Tunnel struct {
	Config    string `toml:"config"`
	Driver    string `toml:"driver"` // auto | kernel | userspace
	Interface string `toml:"interface"`
}

// Group is a named set of processes, filled via `shunt run --group`.
type Group struct {
	Description string `toml:"description"`
}

// Rule maps selectors to a route. Selectors of different kinds are ANDed,
// entries within one kind are ORed. First matching rule wins.
type Rule struct {
	Name  string   `toml:"name"`
	Group []string `toml:"group"`
	CIDR  []string `toml:"cidr"`
	Port  []string `toml:"port"`
	Route string   `toml:"route"`
}

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,9}$`)

// ValidName reports whether s is usable as tunnel or group name. The length
// limit keeps derived interface names ("sh-<name>") within IFNAMSIZ.
func ValidName(s string) bool { return nameRe.MatchString(s) }

// Load reads and validates a config file.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(string(b))
}

// Parse decodes and validates config text.
func Parse(s string) (*Config, error) {
	var c Config
	md, err := toml.Decode(s, &c)
	if err != nil {
		return nil, err
	}
	if und := md.Undecoded(); len(und) > 0 {
		keys := make([]string, len(und))
		for i, k := range und {
			keys[i] = k.String()
		}
		return nil, fmt.Errorf("unknown config keys: %s", strings.Join(keys, ", "))
	}
	c.applyDefaults()
	return &c, c.Validate()
}

func (c *Config) applyDefaults() {
	if c.Daemon.Socket == "" {
		c.Daemon.Socket = "/run/shunt/shuntd.sock"
	}
	if c.Daemon.DefaultRoute == "" {
		c.Daemon.DefaultRoute = "direct"
	}
	for n, t := range c.Tunnels {
		if t.Driver == "" {
			t.Driver = "auto"
		}
		if t.Interface == "" {
			t.Interface = "sh-" + n
		}
		c.Tunnels[n] = t
	}
}

// Validate checks references and syntax of all selectors.
func (c *Config) Validate() error {
	for n, t := range c.Tunnels {
		if !ValidName(n) {
			return fmt.Errorf("tunnel %q: name must match %s", n, nameRe)
		}
		if t.Config == "" {
			return fmt.Errorf("tunnel %q: config path missing", n)
		}
		switch t.Driver {
		case "auto", "kernel", "userspace":
		default:
			return fmt.Errorf("tunnel %q: unknown driver %q", n, t.Driver)
		}
		if len(t.Interface) > 15 {
			return fmt.Errorf("tunnel %q: interface name too long", n)
		}
	}
	for n := range c.Groups {
		if !ValidName(n) {
			return fmt.Errorf("group %q: name must match %s", n, nameRe)
		}
	}
	if _, err := c.ParseRoute(c.Daemon.DefaultRoute); err != nil {
		return fmt.Errorf("daemon.default_route: %w", err)
	}
	for i, r := range c.Rules {
		where := fmt.Sprintf("rule %d (%s)", i+1, r.Name)
		if _, err := c.ParseRoute(r.Route); err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}
		if len(r.Group)+len(r.CIDR)+len(r.Port) == 0 {
			return fmt.Errorf("%s: no selector", where)
		}
		for _, g := range r.Group {
			if _, ok := c.Groups[g]; !ok {
				return fmt.Errorf("%s: unknown group %q", where, g)
			}
		}
		for _, s := range r.CIDR {
			if _, err := ParseCIDR(s); err != nil {
				return fmt.Errorf("%s: %w", where, err)
			}
		}
		for _, s := range r.Port {
			if _, err := ParsePort(s); err != nil {
				return fmt.Errorf("%s: %w", where, err)
			}
		}
	}
	return nil
}

// RouteKind is the type of a route.
type RouteKind int

const (
	RouteDirect RouteKind = iota
	RouteBlock
	RouteTunnel
)

// Route is a parsed route reference.
type Route struct {
	Kind   RouteKind
	Tunnel string
}

func (r Route) String() string {
	switch r.Kind {
	case RouteBlock:
		return "block"
	case RouteTunnel:
		return "tunnel:" + r.Tunnel
	}
	return "direct"
}

// ParseRoute parses "direct", "block" or "tunnel:<name>".
func (c *Config) ParseRoute(s string) (Route, error) {
	switch s {
	case "direct":
		return Route{Kind: RouteDirect}, nil
	case "block":
		return Route{Kind: RouteBlock}, nil
	}
	if n, ok := strings.CutPrefix(s, "tunnel:"); ok {
		if _, exists := c.Tunnels[n]; !exists {
			return Route{}, fmt.Errorf("unknown tunnel %q", n)
		}
		return Route{Kind: RouteTunnel, Tunnel: n}, nil
	}
	return Route{}, fmt.Errorf("invalid route %q (direct | block | tunnel:<name>)", s)
}

// Routes returns every route the config can produce, in stable order:
// direct, block, then tunnels sorted by name.
func (c *Config) Routes() []Route {
	rs := []Route{{Kind: RouteDirect}, {Kind: RouteBlock}}
	names := make([]string, 0, len(c.Tunnels))
	for n := range c.Tunnels {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		rs = append(rs, Route{Kind: RouteTunnel, Tunnel: n})
	}
	return rs
}

// ParseCIDR accepts a prefix or a bare address.
func ParseCIDR(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid cidr %q", s)
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// PortSel is a protocol plus port range.
type PortSel struct {
	Proto    string // tcp | udp
	From, To uint16
}

// ParsePort parses "tcp/22" or "udp/6881-6889".
func ParsePort(s string) (PortSel, error) {
	proto, rng, ok := strings.Cut(s, "/")
	if !ok || (proto != "tcp" && proto != "udp") {
		return PortSel{}, fmt.Errorf("invalid port %q (want tcp/N or udp/N-M)", s)
	}
	lo, hi, isRange := strings.Cut(rng, "-")
	from, err1 := strconv.ParseUint(lo, 10, 16)
	to := from
	var err2 error
	if isRange {
		to, err2 = strconv.ParseUint(hi, 10, 16)
	}
	if err1 != nil || err2 != nil || from == 0 || to < from {
		return PortSel{}, fmt.Errorf("invalid port %q", s)
	}
	return PortSel{Proto: proto, From: uint16(from), To: uint16(to)}, nil
}
