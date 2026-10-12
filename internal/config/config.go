// Package config loads and validates the shuntd configuration (TOML).
package config

import (
	"fmt"
	"net"
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
	Daemon  Daemon            `toml:"daemon" json:"daemon"`
	DNS     DNS               `toml:"dns" json:"dns"`
	Tunnels map[string]Tunnel `toml:"tunnel,omitempty" json:"tunnel,omitempty"`
	Groups  map[string]Group  `toml:"group,omitempty" json:"group,omitempty"`
	Rules   []Rule            `toml:"rule,omitempty" json:"rule,omitempty"`
	// Networks change the default route depending on where you are.
	Networks []Network `toml:"network,omitempty" json:"network,omitempty"`
}

// Network is a known network (home, office). While connected to it, its
// default_route replaces daemon.default_route; everywhere else the daemon's
// default applies. All given criteria must match; within one, any entry.
type Network struct {
	Name string `toml:"name" json:"name"`
	// SSID: Wi-Fi names. Easy to fake: combine with gateway_mac when the
	// profile relaxes protection (e.g. default_route = "direct").
	SSID []string `toml:"ssid,omitempty" json:"ssid,omitempty"`
	// GatewayMAC: MAC address of the default gateway (router).
	GatewayMAC   []string `toml:"gateway_mac,omitempty" json:"gateway_mac,omitempty"`
	DefaultRoute string   `toml:"default_route" json:"default_route"`
}

// MatchNetwork returns the first network matching the current SSID and
// gateway MAC, or nil.
func (c *Config) MatchNetwork(ssid, gatewayMAC string) *Network {
	gatewayMAC = strings.ToLower(gatewayMAC)
	for i, n := range c.Networks {
		if len(n.SSID) > 0 && (ssid == "" || !contains(n.SSID, ssid)) {
			continue
		}
		if len(n.GatewayMAC) > 0 {
			ok := false
			for _, m := range n.GatewayMAC {
				ok = ok || (gatewayMAC != "" && strings.EqualFold(m, gatewayMAC))
			}
			if !ok {
				continue
			}
		}
		return &c.Networks[i]
	}
	return nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// Daemon holds daemon wide settings.
type Daemon struct {
	Socket      string `toml:"socket,omitempty" json:"socket,omitempty"`
	SocketGroup string `toml:"socket_group,omitempty" json:"socket_group,omitempty"`
	// CgroupRoot is the cgroup (relative to the cgroup2 mount) shuntd owns.
	// Empty means: the cgroup shuntd was started in (systemd Delegate=yes).
	CgroupRoot   string `toml:"cgroup_root,omitempty" json:"cgroup_root,omitempty"`
	DefaultRoute string `toml:"default_route,omitempty" json:"default_route,omitempty"`
	// APIAuth: "polkit" (default) – config changes, reload and lifting panic
	// need root or polkit authorization; "group" – every socket_group
	// member may do everything.
	APIAuth string `toml:"api_auth,omitempty" json:"api_auth,omitempty"`
}

// DNS configures the per-route DNS proxy.
type DNS struct {
	// Disabled turns DNS routing off (not recommended: DNS then leaks
	// through whatever resolver the system uses).
	Disabled bool `toml:"disabled,omitempty" json:"disabled,omitempty"`
	// Direct names the upstream for the direct route. Empty means the
	// system's resolvers (from systemd-resolved or /etc/resolv.conf).
	Direct string `toml:"direct,omitempty" json:"direct,omitempty"`
	// AllowDoH / AllowDoT disable the blocking of encrypted DNS that would
	// bypass Shunt (known DoH hosts get NXDOMAIN, port 853 is rejected).
	AllowDoH bool                `toml:"allow_doh,omitempty" json:"allow_doh,omitempty"`
	AllowDoT bool                `toml:"allow_dot,omitempty" json:"allow_dot,omitempty"`
	Upstream map[string]Upstream `toml:"upstream,omitempty" json:"upstream,omitempty"`
}

// Upstream is a DNS server Shunt forwards to.
type Upstream struct {
	// Addr: "1.2.3.4", "udp://1.2.3.4:53", "tcp://…", "tls://1.2.3.4:853",
	// "https://1.2.3.4/dns-query". Hosts must be IP literals: resolving the
	// resolver would need a resolver, and that one would leak.
	Addr string `toml:"addr,omitempty" json:"addr,omitempty"`
	// TLSName is the certificate name for tls:// and https:// upstreams.
	TLSName string `toml:"tls_name,omitempty" json:"tls_name,omitempty"`
}

// Tunnel references a wg-quick file or an OpenVPN client config.
type Tunnel struct {
	Config string `toml:"config,omitempty" json:"config,omitempty"`
	// Driver: auto | kernel | userspace (WireGuard), openvpn.
	Driver    string `toml:"driver,omitempty" json:"driver,omitempty"`
	Interface string `toml:"interface,omitempty" json:"interface,omitempty"`
	// DNS names the upstream used for this tunnel. Empty means the DNS=
	// servers from the wg-quick file (or the ones an OpenVPN server
	// pushes), queried through the tunnel.
	DNS string `toml:"dns" json:"dns"`
	// Auth (OpenVPN): file with username and password, one per line.
	Auth string `toml:"auth,omitempty" json:"auth,omitempty"`
	// Via makes this tunnel a second hop: its encrypted packets travel
	// through that tunnel ("tunnel:<name>") instead of the local network.
	Via string `toml:"via,omitempty" json:"via,omitempty"`
}

// IsOpenVPN reports whether the tunnel is run by openvpn.
func (t Tunnel) IsOpenVPN() bool { return t.Driver == "openvpn" }

// Group is a named set of processes, filled via `shunt run --group`.
type Group struct {
	Description string `toml:"description,omitempty" json:"description,omitempty"`
}

// Rule maps selectors to a route. Selectors of different kinds are ANDed,
// entries within one kind are ORed. First matching rule wins.
type Rule struct {
	Name   string   `toml:"name,omitempty" json:"name,omitempty"`
	Group  []string `toml:"group,omitempty" json:"group,omitempty"`
	CIDR   []string `toml:"cidr,omitempty" json:"cidr,omitempty"`
	Port   []string `toml:"port,omitempty" json:"port,omitempty"`
	Domain []string `toml:"domain,omitempty" json:"domain,omitempty"`
	// App selects programs automatically when they start (no `shunt run`
	// needed): "firefox" (process name), "exe:/usr/bin/foo", "flatpak:<app id>".
	App []string `toml:"app,omitempty" json:"app,omitempty"`
	// Args narrows app: the command line must contain one of these, e.g.
	// args = ["-P sm"] to catch one Firefox profile.
	Args  []string `toml:"args,omitempty" json:"args,omitempty"`
	Route string   `toml:"route,omitempty" json:"route,omitempty"`
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
		case "auto", "kernel", "userspace", "openvpn":
		default:
			return fmt.Errorf("tunnel %q: unknown driver %q (auto | kernel | userspace | openvpn)", n, t.Driver)
		}
		if t.Auth != "" && !t.IsOpenVPN() {
			return fmt.Errorf("tunnel %q: auth is only for driver = \"openvpn\"", n)
		}
		if t.Via != "" {
			r, err := c.ParseRoute(t.Via)
			if err != nil || r.Kind != RouteTunnel {
				return fmt.Errorf("tunnel %q: via must be \"tunnel:<name>\"", n)
			}
		}
		if len(t.Interface) > 15 {
			return fmt.Errorf("tunnel %q: interface name too long", n)
		}
		if t.DNS != "" {
			if _, ok := c.DNS.Upstream[t.DNS]; !ok {
				return fmt.Errorf("tunnel %q: unknown dns upstream %q", n, t.DNS)
			}
		}
	}
	seenNet := map[string]bool{}
	for i, n := range c.Networks {
		where := fmt.Sprintf("network %d (%s)", i+1, n.Name)
		if n.Name == "" || seenNet[n.Name] {
			return fmt.Errorf("%s: needs a unique name", where)
		}
		seenNet[n.Name] = true
		if len(n.SSID)+len(n.GatewayMAC) == 0 {
			return fmt.Errorf("%s: needs ssid and/or gateway_mac", where)
		}
		for _, m := range n.GatewayMAC {
			if hw, err := net.ParseMAC(m); err != nil || len(hw) != 6 {
				return fmt.Errorf("%s: invalid gateway_mac %q", where, m)
			}
		}
		if _, err := c.ParseRoute(n.DefaultRoute); err != nil {
			return fmt.Errorf("%s: default_route: %w", where, err)
		}
	}
	if err := c.checkHops(); err != nil {
		return err
	}
	if c.DNS.Direct != "" {
		if _, ok := c.DNS.Upstream[c.DNS.Direct]; !ok {
			return fmt.Errorf("dns.direct: unknown upstream %q", c.DNS.Direct)
		}
	}
	for n, u := range c.DNS.Upstream {
		if _, err := ParseUpstream(u); err != nil {
			return fmt.Errorf("dns.upstream.%s: %w", n, err)
		}
	}
	for n := range c.Groups {
		if !ValidName(n) {
			return fmt.Errorf("group %q: name must match %s", n, nameRe)
		}
	}
	switch c.Daemon.APIAuth {
	case "", "polkit", "group":
	default:
		return fmt.Errorf("daemon.api_auth: %q (polkit | group)", c.Daemon.APIAuth)
	}
	if _, err := c.ParseRoute(c.Daemon.DefaultRoute); err != nil {
		return fmt.Errorf("daemon.default_route: %w", err)
	}
	for i, r := range c.Rules {
		where := fmt.Sprintf("rule %d (%s)", i+1, r.Name)
		if _, err := c.ParseRoute(r.Route); err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}
		if len(r.Args) > 0 && len(r.App) == 0 {
			return fmt.Errorf("%s: args needs app", where)
		}
		if len(r.App) > 0 {
			if len(r.Group)+len(r.Domain) > 0 {
				return fmt.Errorf("%s: app cannot be combined with group or domain", where)
			}
			for _, a := range r.App {
				if _, err := ParseAppSel(a); err != nil {
					return fmt.Errorf("%s: %w", where, err)
				}
			}
		}
		if len(r.Group)+len(r.CIDR)+len(r.Port)+len(r.Domain)+len(r.App) == 0 {
			return fmt.Errorf("%s: no selector", where)
		}
		if len(r.Domain) > 0 {
			if c.DNS.Disabled {
				return fmt.Errorf("%s: domain rules need DNS routing (dns.disabled = true)", where)
			}
			// The DNS proxy only knows the route a query came from, not the
			// group, and domain + cidr would be ambiguous (AND or OR?).
			if len(r.Group)+len(r.CIDR) > 0 {
				return fmt.Errorf("%s: domain can only be combined with port", where)
			}
			for _, d := range r.Domain {
				if NormalizeDomain(d) == "" {
					return fmt.Errorf("%s: invalid domain %q", where, d)
				}
			}
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

// checkHops rejects via chains that loop.
func (c *Config) checkHops() error {
	for n := range c.Tunnels {
		seen := map[string]bool{n: true}
		for cur := n; c.Tunnels[cur].Via != ""; {
			cur = strings.TrimPrefix(c.Tunnels[cur].Via, "tunnel:")
			if seen[cur] {
				return fmt.Errorf("tunnel %q: via chain loops back to %q", n, cur)
			}
			seen[cur] = true
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

// NormalizeDomain lowercases, strips a leading "*." and the trailing dot.
// A rule for "example.com" also covers all its subdomains. Returns "" if
// the name is not usable.
func NormalizeDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimPrefix(d, "*.")
	d = strings.TrimSuffix(d, ".")
	if d == "" || strings.ContainsAny(d, " /*\\\"") || len(d) > 253 {
		return ""
	}
	return d
}

// UpstreamSpec is a parsed upstream address.
type UpstreamSpec struct {
	Proto   string         // udp | tcp | tls | https
	Addr    netip.AddrPort // server
	Path    string         // https only
	TLSName string
}

// ParseUpstream parses an Upstream.
func ParseUpstream(u Upstream) (UpstreamSpec, error) {
	s := u.Addr
	proto := "udp"
	if p, rest, ok := strings.Cut(s, "://"); ok {
		proto, s = p, rest
	}
	path := ""
	if proto == "https" {
		if i := strings.IndexByte(s, '/'); i >= 0 {
			s, path = s[:i], s[i:]
		}
		if path == "" {
			path = "/dns-query"
		}
	}
	defPort := map[string]uint16{"udp": 53, "tcp": 53, "tls": 853, "https": 443}[proto]
	if defPort == 0 {
		return UpstreamSpec{}, fmt.Errorf("unknown protocol %q", proto)
	}
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		a, aerr := netip.ParseAddr(strings.Trim(s, "[]"))
		if aerr != nil {
			return UpstreamSpec{}, fmt.Errorf("%q: host must be an IP address", u.Addr)
		}
		ap = netip.AddrPortFrom(a, defPort)
	}
	if (proto == "tls" || proto == "https") && u.TLSName == "" {
		return UpstreamSpec{}, fmt.Errorf("%q: tls_name is required for %s", u.Addr, proto)
	}
	return UpstreamSpec{Proto: proto, Addr: ap, Path: path, TLSName: u.TLSName}, nil
}

// AppSel selects processes by name, executable path or Flatpak app id.
type AppSel struct {
	Kind  string // name | exe | flatpak
	Value string
}

func (a AppSel) String() string {
	if a.Kind == "name" {
		return a.Value
	}
	return a.Kind + ":" + a.Value
}

var flatpakIDRe = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// ParseAppSel parses "firefox", "exe:/usr/bin/foo" or "flatpak:org.x.Y".
func ParseAppSel(s string) (AppSel, error) {
	switch {
	case strings.HasPrefix(s, "exe:"):
		v := strings.TrimPrefix(s, "exe:")
		if !strings.HasPrefix(v, "/") {
			return AppSel{}, fmt.Errorf("app %q: exe path must be absolute", s)
		}
		return AppSel{Kind: "exe", Value: v}, nil
	case strings.HasPrefix(s, "flatpak:"):
		v := strings.TrimPrefix(s, "flatpak:")
		if !flatpakIDRe.MatchString(v) {
			return AppSel{}, fmt.Errorf("app %q: invalid flatpak id", s)
		}
		return AppSel{Kind: "flatpak", Value: v}, nil
	}
	if s == "" || strings.ContainsAny(s, "/:") || len(s) > 255 {
		return AppSel{}, fmt.Errorf("app %q: use a process name, exe:/path or flatpak:<id>", s)
	}
	return AppSel{Kind: "name", Value: s}, nil
}

// Encode writes the config as TOML. Values equal to the built-in defaults
// are left out so the file stays readable. Comments are not preserved.
func (c *Config) Encode() ([]byte, error) {
	cp := *c
	if cp.Daemon.Socket == "/run/shunt/shuntd.sock" {
		cp.Daemon.Socket = ""
	}
	cp.Tunnels = map[string]Tunnel{}
	for n, t := range c.Tunnels {
		if t.Interface == "sh-"+n {
			t.Interface = ""
		}
		if t.Driver == "auto" {
			t.Driver = ""
		}
		cp.Tunnels[n] = t
	}
	var b strings.Builder
	b.WriteString("# The Shunt configuration - saved by the Shunt UI.\n# (Comments are not kept when saving from the form editor.)\n\n")
	if err := toml.NewEncoder(&b).Encode(cp); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}
