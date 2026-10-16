// Package tsconf reads the config file of a Tailscale/Headscale tunnel
// ("<name>.ts"): a few key = value lines. It holds the auth key, so shuntd
// insists on mode 600 like for the other tunnel files.
//
//	login_server = http://headscale.example:8080   # empty: Tailscale's own
//	auth_key     = hskey-auth-...                  # or tskey-auth-...
//	hostname     = my-laptop                       # name in the tailnet (optional)
//	exit_node    = 100.64.0.1                      # tailnet IP or name (optional)
//
// Without exit_node the tunnel reaches the tailnet (100.64.0.0/10) only;
// with it, everything routed into the tunnel leaves through that node.
package tsconf

import (
	"bufio"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// Config is a parsed tunnel file.
type Config struct {
	LoginServer string
	AuthKey     string
	Hostname    string
	ExitNode    string
}

var hostRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,62}[A-Za-z0-9])?$`)

// ExitNodeAddr returns the exit node as an address, if it is one.
func (c *Config) ExitNodeAddr() (netip.Addr, bool) {
	a, err := netip.ParseAddr(c.ExitNode)
	return a, err == nil
}

// Prefixes are the destinations the tunnel's route carries.
func (c *Config) Prefixes() []netip.Prefix {
	if c.ExitNode != "" {
		return []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	}
	return []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")}
}

// ParseFile reads and checks a tunnel file.
func ParseFile(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	c := &Config{}
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		l := sc.Text()
		if i := strings.Index(l, "#"); i >= 0 {
			l = l[:i]
		}
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			return nil, fmt.Errorf("%s:%d: expected key = value", path, n)
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "login_server":
			c.LoginServer = v
		case "auth_key":
			c.AuthKey = v
		case "hostname":
			c.Hostname = v
		case "exit_node":
			c.ExitNode = v
		default:
			return nil, fmt.Errorf("%s:%d: unknown key %q (login_server, auth_key, hostname, exit_node)", path, n, k)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return c, c.Validate()
}

// Validate checks values that end up on a command line.
func (c *Config) Validate() error {
	if c.LoginServer != "" {
		u, err := url.Parse(c.LoginServer)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("login_server %q: expected http(s)://host[:port]", c.LoginServer)
		}
	}
	if c.AuthKey == "" {
		return fmt.Errorf("auth_key missing (headscale: `headscale preauthkeys create`)")
	}
	if strings.ContainsAny(c.AuthKey, " \t\r\n\"'\\") {
		return fmt.Errorf("auth_key has odd characters")
	}
	if c.Hostname != "" && !hostRe.MatchString(c.Hostname) {
		return fmt.Errorf("hostname %q: letters, digits, '-' and '.' only", c.Hostname)
	}
	if c.ExitNode != "" {
		if _, ok := c.ExitNodeAddr(); !ok && !hostRe.MatchString(c.ExitNode) {
			return fmt.Errorf("exit_node %q: a tailnet IP or a node name", c.ExitNode)
		}
	}
	return nil
}
