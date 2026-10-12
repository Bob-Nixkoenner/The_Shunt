// Package wgconf parses WireGuard configuration files in the wg-quick format.
//
// Only the data needed to bring up a tunnel is taken over. wg-quick specific
// hooks (PreUp, PostUp, ...) and routing knobs (Table, FwMark) are ignored on
// purpose: Shunt owns routing, and executing shell hooks from an imported file
// as root would be a gift to anyone who can hand the user a config.
package wgconf

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// Key is a WireGuard Curve25519 key.
type Key [32]byte

func parseKey(s string) (Key, error) {
	var k Key
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != len(k) {
		return k, fmt.Errorf("invalid key")
	}
	copy(k[:], b)
	return k, nil
}

func (k Key) String() string { return base64.StdEncoding.EncodeToString(k[:]) }

// IsZero reports whether the key is unset.
func (k Key) IsZero() bool { return k == Key{} }

// Config is a parsed wg-quick file.
type Config struct {
	PrivateKey Key
	Addresses  []netip.Prefix
	DNS        []string
	MTU        int
	ListenPort int
	Peers      []Peer
	// Ignored lists keys that were present but deliberately not applied.
	Ignored []string
}

// Peer is one [Peer] section.
type Peer struct {
	PublicKey           Key
	PresharedKey        Key
	Endpoint            string // host:port, host may be a name (resolved by the tunnel manager)
	AllowedIPs          []netip.Prefix
	PersistentKeepalive int
}

// HasIPv4 reports whether the interface has an IPv4 address.
func (c *Config) HasIPv4() bool { return c.hasFamily(true) }

// HasIPv6 reports whether the interface has an IPv6 address.
func (c *Config) HasIPv6() bool { return c.hasFamily(false) }

func (c *Config) hasFamily(v4 bool) bool {
	for _, a := range c.Addresses {
		if a.Addr().Is4() == v4 {
			return true
		}
	}
	return false
}

// ParseFile reads and parses a wg-quick file.
func ParseFile(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	c, err := Parse(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// Parse parses a wg-quick config.
func Parse(r io.Reader) (*Config, error) {
	c := &Config{}
	var peer *Peer
	section := ""
	sc := bufio.NewScanner(r)
	ln := 0
	for sc.Scan() {
		ln++
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			switch section {
			case "interface":
			case "peer":
				c.Peers = append(c.Peers, Peer{})
				peer = &c.Peers[len(c.Peers)-1]
			default:
				return nil, fmt.Errorf("line %d: unknown section [%s]", ln, section)
			}
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: expected key = value", ln)
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		var err error
		switch section {
		case "interface":
			err = c.setInterface(k, v)
		case "peer":
			err = peer.set(k, v)
		default:
			err = fmt.Errorf("key outside of a section")
		}
		if err != nil {
			return nil, fmt.Errorf("line %d (%s): %w", ln, k, err)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return c, c.validate()
}

func (c *Config) setInterface(k, v string) error {
	var err error
	switch k {
	case "privatekey":
		c.PrivateKey, err = parseKey(v)
	case "address":
		for _, s := range splitList(v) {
			p, perr := netip.ParsePrefix(s)
			if perr != nil {
				a, aerr := netip.ParseAddr(s)
				if aerr != nil {
					return perr
				}
				p = netip.PrefixFrom(a, a.BitLen())
			}
			c.Addresses = append(c.Addresses, p)
		}
	case "dns":
		c.DNS = append(c.DNS, splitList(v)...)
	case "mtu":
		c.MTU, err = strconv.Atoi(v)
	case "listenport":
		c.ListenPort, err = strconv.Atoi(v)
	case "table", "fwmark", "preup", "postup", "predown", "postdown", "saveconfig":
		c.Ignored = append(c.Ignored, k)
	default:
		return fmt.Errorf("unknown key")
	}
	return err
}

func (p *Peer) set(k, v string) error {
	var err error
	switch k {
	case "publickey":
		p.PublicKey, err = parseKey(v)
	case "presharedkey":
		p.PresharedKey, err = parseKey(v)
	case "endpoint":
		p.Endpoint = v
	case "allowedips":
		for _, s := range splitList(v) {
			pr, perr := netip.ParsePrefix(s)
			if perr != nil {
				return perr
			}
			p.AllowedIPs = append(p.AllowedIPs, pr.Masked())
		}
	case "persistentkeepalive":
		if v == "off" {
			return nil
		}
		p.PersistentKeepalive, err = strconv.Atoi(v)
	default:
		return fmt.Errorf("unknown key")
	}
	return err
}

func (c *Config) validate() error {
	if c.PrivateKey.IsZero() {
		return fmt.Errorf("missing PrivateKey")
	}
	if len(c.Addresses) == 0 {
		return fmt.Errorf("missing Address")
	}
	if len(c.Peers) == 0 {
		return fmt.Errorf("no [Peer]")
	}
	for i, p := range c.Peers {
		if p.PublicKey.IsZero() {
			return fmt.Errorf("peer %d: missing PublicKey", i+1)
		}
	}
	return nil
}

func splitList(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}
