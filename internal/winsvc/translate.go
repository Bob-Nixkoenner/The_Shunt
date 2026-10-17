package winsvc

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
)

// Translate turns shunt.toml (the format of the Linux daemon and its web UI)
// into the JSON config of internal/splitstack. read returns the contents of
// a file named in the config (tunnel config, auth file). Warnings name what
// the Windows service does not do (yet); the rest of the file still applies.
func Translate(c *config.Config, read func(path string) ([]byte, error)) (js string, warnings []string, err error) {
	warn := func(f string, a ...any) { warnings = append(warnings, fmt.Sprintf(f, a...)) }

	// a disabled tunnel stays in the file but its route blocks
	disabled := map[string]bool{}
	for n, t := range c.Tunnels {
		disabled[n] = t.Disabled
	}
	route := func(s string) (string, error) {
		r, err := c.ParseRoute(s)
		if err != nil {
			return "", err
		}
		switch r.Kind {
		case config.RouteDirect, config.RouteBlock:
			return r.String(), nil
		case config.RouteTunnel:
			if disabled[r.Tunnel] {
				return "block", nil
			}
			return r.String(), nil
		case config.RouteLink:
			return r.String(), nil // resolved by the engine: direct while on that kind of network
		}
		return "", fmt.Errorf("route %q is not available on Windows", s)
	}

	type tunnelJS struct {
		Name string `json:"name"`
		Type string `json:"type,omitempty"`
		Conf string `json:"conf"`
		User string `json:"user,omitempty"`
		Pass string `json:"pass,omitempty"`
		Via  string `json:"via,omitempty"`
	}
	type networkJS struct {
		Name    string   `json:"name"`
		SSID    []string `json:"ssid"`
		Default string   `json:"default"`
	}
	type ruleJS struct {
		Name    string   `json:"name"`
		Apps    []string `json:"apps"`
		Domains []string `json:"domains"`
		CIDR    []string `json:"cidr"`
		Ports   []string `json:"ports"`
		Route   string   `json:"route"`
	}
	out := struct {
		Tunnels  []tunnelJS        `json:"tunnels"`
		Default  string            `json:"default"`
		Apps     map[string]string `json:"apps"`
		Direct   string            `json:"direct_dns,omitempty"`
		Networks []networkJS       `json:"networks"`
		Rules    []ruleJS          `json:"rules"`
	}{Apps: map[string]string{}, Tunnels: []tunnelJS{}, Networks: []networkJS{}, Rules: []ruleJS{}}

	for _, name := range sortedKeys(c.Tunnels) {
		t := c.Tunnels[name]
		if t.Disabled {
			continue
		}
		b, err := read(t.Config)
		if err != nil {
			return "", nil, fmt.Errorf("tunnel %q: %w", name, err)
		}
		tj := tunnelJS{Name: name, Conf: string(b)}
		if t.IsTailscale() {
			tj.Type = "tailscale"
		}
		if t.IsOpenVPN() {
			tj.Type = "openvpn"
			warn("tunnel %q: OpenVPN is not available on Windows yet, the tunnel stays down", name)
			if t.Auth != "" {
				ab, err := read(t.Auth)
				if err != nil {
					return "", nil, fmt.Errorf("tunnel %q: %w", name, err)
				}
				lines := strings.SplitN(strings.TrimRight(string(ab), "\r\n"), "\n", 2)
				tj.User = strings.TrimSpace(lines[0])
				if len(lines) > 1 {
					tj.Pass = strings.TrimSpace(lines[1])
				}
			}
		}
		if t.Via != "" {
			if r, err := c.ParseRoute(t.Via); err == nil && r.Kind == config.RouteTunnel {
				tj.Via = r.Tunnel
			} else {
				warn("tunnel %q: via %q is not available on Windows yet", name, t.Via)
			}
		}
		if t.AllowLAN {
			warn("tunnel %q: allow_lan is not available on Windows yet", name)
		}
		out.Tunnels = append(out.Tunnels, tj)
	}

	if out.Default, err = route(c.Daemon.DefaultRoute); err != nil {
		return "", nil, fmt.Errorf("daemon.default_route: %w", err)
	}

	for _, n := range c.Networks {
		nj := networkJS{Name: n.Name, SSID: n.SSID}
		if len(n.GatewayMAC) > 0 {
			warn("network %q: gateway_mac is not used on Windows yet (only the Wi-Fi name)", n.Name)
		}
		if n.DefaultRoute != "" {
			if nj.Default, err = route(n.DefaultRoute); err != nil {
				return "", nil, fmt.Errorf("network %q: %w", n.Name, err)
			}
		}
		out.Networks = append(out.Networks, nj)
	}

	for i, r := range c.Rules {
		where := fmt.Sprintf("rule %d (%s)", i+1, r.Name)
		if r.Route == "" {
			warn("%s: only sets dns_filter, which Windows does not have yet", where)
			continue
		}
		rt, err := route(r.Route)
		if err != nil {
			return "", nil, fmt.Errorf("%s: %w", where, err)
		}
		apps := appIDs(r.App, func(s string) { warn("%s: %s", where, s) })
		if len(r.Group) > 0 {
			warn("%s: groups are not available on Windows (use app rules)", where)
			if len(apps) == 0 {
				continue
			}
		}
		if len(r.Args)+len(r.Network) > 0 || r.OverrideExplicit || r.DNSFilter != "" {
			warn("%s: args, network, override_explicit and dns_filter are ignored on Windows", where)
		}
		if len(r.CIDR)+len(r.Port)+len(r.Domain) > 0 {
			out.Rules = append(out.Rules, ruleJS{Name: r.Name, Apps: apps, Domains: r.Domain, CIDR: r.CIDR, Ports: r.Port, Route: rt})
			continue
		}
		if len(apps) == 0 {
			warn("%s: selects nothing (no app, address, port or domain)", where)
			continue
		}
		for _, a := range apps {
			if _, taken := out.Apps[a]; !taken { // first rule wins, as on Linux
				out.Apps[a] = rt
			}
		}
	}

	if d := c.DNS.Direct; d != "" {
		if ip, ok := plainIP(c.DNS.Upstream[d].Addr); ok {
			out.Direct = ip
		} else {
			warn("dns.direct %q: only plain IP addresses (1.1.1.1 or udp://1.1.1.1) work on Windows yet", d)
		}
	}
	// The DNS filter works with the default level only (the service keeps
	// the lists, see Manager.ApplyFilter); levels per tunnel or network
	// are not applied yet.
	scoped := false
	for _, t := range c.Tunnels {
		scoped = scoped || t.DNSFilter != ""
	}
	for _, n := range c.Networks {
		scoped = scoped || n.DNSFilter != ""
	}
	if scoped { // rules with their own level are warned about with the rule
		warn("the DNS filter level of single tunnels and networks is not available on Windows yet: [dns_filter] default applies everywhere")
	}
	if c.Firewall != nil && c.Firewall.Mode != "" && c.Firewall.Mode != config.FirewallOff {
		warn("the app firewall is not available on Windows yet")
	}

	b, err := json.Marshal(out)
	return string(b), warnings, err
}

// appIDs maps [[rule]] app selectors to Windows app IDs: a process name
// becomes its exe name ("firefox" -> "firefox.exe", matches wherever it is
// installed), exe:<path> the lower-case path.
func appIDs(sel []string, warn func(string)) []string {
	var ids []string
	for _, s := range sel {
		a, err := config.ParseAppSel(s)
		if err != nil {
			warn(err.Error())
			continue
		}
		switch a.Kind {
		case "name":
			n := strings.ToLower(a.Value)
			if !strings.Contains(n, ".") {
				n += ".exe"
			}
			ids = append(ids, n)
		case "exe":
			ids = append(ids, strings.ToLower(a.Value))
		default:
			warn(fmt.Sprintf("app %q is not available on Windows", s))
		}
	}
	return ids
}

func plainIP(addr string) (string, bool) {
	a := strings.TrimPrefix(addr, "udp://")
	if h, _, ok := strings.Cut(a, ":"); ok && !strings.Contains(a, "::") && strings.Count(a, ":") == 1 {
		a = h
	}
	ip, err := netip.ParseAddr(a)
	if err != nil {
		return "", false
	}
	return ip.String(), true
}

func sortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	for i := 1; i < len(ks); i++ {
		for j := i; j > 0 && ks[j-1] > ks[j]; j-- {
			ks[j-1], ks[j] = ks[j], ks[j-1]
		}
	}
	return ks
}

var errNoFile = errors.New("file not found")
