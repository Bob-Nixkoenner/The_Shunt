// Package mullvad talks to Mullvad's public API: log in with an account
// number, register a WireGuard key as a device, read the relay list and turn
// a chosen relay into a wg-quick file. The result is an ordinary WireGuard
// tunnel for Shunt; nothing here touches routing.
package mullvad

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
)

// BaseURL is Mullvad's API.
const BaseURL = "https://api.mullvad.net"

// Port is the WireGuard port every relay accepts.
const Port = 51820

// Client calls the API. The zero value uses BaseURL and a 20 s timeout.
type Client struct {
	Base string
	HTTP *http.Client
}

func (c *Client) base() string {
	if c.Base != "" {
		return c.Base
	}
	return BaseURL
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 20 * time.Second}
}

// APIError is an error answer from Mullvad.
type APIError struct {
	Status int
	Code   string
	Text   string
}

func (e *APIError) Error() string {
	switch e.Code {
	case "INVALID_ACCOUNT":
		return "Mullvad: this account number is not valid"
	case "MAX_DEVICES_REACHED":
		return "Mullvad: this account already has 5 devices; remove one at mullvad.net/account first"
	case "KEY_ALREADY_IN_USE":
		return "Mullvad: this key is already registered"
	}
	if e.Text != "" {
		return fmt.Sprintf("Mullvad: %s (HTTP %d)", e.Text, e.Status)
	}
	return fmt.Sprintf("Mullvad: HTTP %d", e.Status)
}

func (c *Client) do(ctx context.Context, method, path, token string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base()+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.http().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		ae := &APIError{Status: resp.StatusCode}
		var e struct {
			Code  string `json:"code"`
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &e) == nil {
			ae.Code, ae.Text = e.Code, e.Error
		}
		return ae
	}
	if out == nil || len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, out)
}

var accountRe = regexp.MustCompile(`^[0-9]{16}$`)

// NormalizeAccount removes spaces and checks the 16-digit account number.
func NormalizeAccount(s string) (string, error) {
	s = strings.NewReplacer(" ", "", "-", "").Replace(strings.TrimSpace(s))
	if !accountRe.MatchString(s) {
		return "", errors.New("the Mullvad account number has 16 digits")
	}
	return s, nil
}

// Token exchanges the account number for a short-lived access token.
func (c *Client) Token(ctx context.Context, account string) (string, error) {
	var r struct {
		AccessToken string `json:"access_token"`
	}
	if err := c.do(ctx, "POST", "/auth/v1/token", "", map[string]string{"account_number": account}, &r); err != nil {
		return "", err
	}
	if r.AccessToken == "" {
		return "", errors.New("Mullvad: no access token in the answer")
	}
	return r.AccessToken, nil
}

// Device is a registered WireGuard key.
type Device struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	IPv4 string `json:"ipv4_address"` // "10.x.x.x/32"
	IPv6 string `json:"ipv6_address"` // "fc00:…/128"
}

// AddDevice registers a public key. The account may hold 5 devices.
func (c *Client) AddDevice(ctx context.Context, token, pubkey string) (*Device, error) {
	var d Device
	err := c.do(ctx, "POST", "/accounts/v1/devices", token, map[string]any{"pubkey": pubkey, "hijack_dns": false}, &d)
	if err != nil {
		return nil, err
	}
	if d.ID == "" || d.IPv4 == "" {
		return nil, errors.New("Mullvad: incomplete device answer")
	}
	return &d, nil
}

var deviceIDRe = regexp.MustCompile(`^[0-9a-zA-Z-]{1,64}$`)

// DeleteDevice removes a device (frees one of the 5 slots).
func (c *Client) DeleteDevice(ctx context.Context, token, id string) error {
	if !deviceIDRe.MatchString(id) {
		return errors.New("bad device id")
	}
	return c.do(ctx, "DELETE", "/accounts/v1/devices/"+id, token, nil, nil)
}

// NewKey makes a WireGuard key pair (base64).
func NewKey() (priv, pub string, err error) {
	var k [32]byte
	if _, err = rand.Read(k[:]); err != nil {
		return "", "", err
	}
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
	p, err := curve25519.X25519(k[:], curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(k[:]), base64.StdEncoding.EncodeToString(p), nil
}

// Relay is one WireGuard server.
type Relay struct {
	Hostname string `json:"hostname"`
	Location string `json:"location"` // "de-fra"
	Active   bool   `json:"active"`
	Owned    bool   `json:"owned"`
	Provider string `json:"provider,omitempty"`
	IPv4     string `json:"ipv4_addr_in"`
	IPv6     string `json:"ipv6_addr_in,omitempty"`
	PubKey   string `json:"public_key"`
	Weight   int    `json:"weight"`
	// IncludeInCountry: the relay takes part in "any city in this country".
	IncludeInCountry bool `json:"include_in_country"`
}

// Location is a city.
type Location struct {
	Country string `json:"country"`
	City    string `json:"city"`
}

// RelayList is the public relay list.
type RelayList struct {
	Locations map[string]Location `json:"locations"`
	WireGuard struct {
		Gateway string  `json:"ipv4_gateway"`
		Relays  []Relay `json:"relays"`
	} `json:"wireguard"`
}

// Relays loads the relay list (no login needed).
func (c *Client) Relays(ctx context.Context) (*RelayList, error) {
	var l RelayList
	if err := c.do(ctx, "GET", "/public/relays/wireguard/v2", "", nil, &l); err != nil {
		return nil, err
	}
	if len(l.WireGuard.Relays) == 0 {
		return nil, errors.New("Mullvad: empty relay list")
	}
	return &l, nil
}

// City and Country group the relay list for a choice menu.
type City struct {
	Code    string   `json:"code"` // "de-fra"
	Name    string   `json:"name"`
	Servers int      `json:"servers"`
	Hosts   []string `json:"hosts"`
}

type Country struct {
	Code    string `json:"code"` // "de"
	Name    string `json:"name"`
	Servers int    `json:"servers"`
	Cities  []City `json:"cities"`
}

func countryCode(loc string) string {
	if i := strings.IndexByte(loc, '-'); i > 0 {
		return loc[:i]
	}
	return loc
}

// Countries lists countries and cities that have active servers.
func (l *RelayList) Countries() []Country {
	perCity := map[string][]string{}
	for _, r := range l.WireGuard.Relays {
		if _, ok := l.Locations[r.Location]; ok && r.Active {
			perCity[r.Location] = append(perCity[r.Location], r.Hostname)
		}
	}
	byCC := map[string]*Country{}
	for code, hosts := range perCity {
		sort.Strings(hosts)
		n := len(hosts)
		loc := l.Locations[code]
		cc := countryCode(code)
		c := byCC[cc]
		if c == nil {
			c = &Country{Code: cc, Name: loc.Country}
			byCC[cc] = c
		}
		c.Servers += n
		c.Cities = append(c.Cities, City{Code: code, Name: loc.City, Servers: n, Hosts: hosts})
	}
	out := make([]Country, 0, len(byCC))
	for _, c := range byCC {
		sort.Slice(c.Cities, func(i, j int) bool { return c.Cities[i].Name < c.Cities[j].Name })
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Choice is what the user picks: a country ("de"), a city ("de-fra") or one
// server ("de-fra-wg-001"). Empty = any.
type Choice struct {
	Country  string
	City     string
	Hostname string
}

var hostRe = regexp.MustCompile(`^[a-z0-9-]{3,40}$`)

// Pick chooses an active relay. Several matches: random, by weight.
func (l *RelayList) Pick(ch Choice) (*Relay, error) {
	var cand []Relay
	for _, r := range l.WireGuard.Relays {
		if !r.Active {
			continue
		}
		switch {
		case ch.Hostname != "":
			if r.Hostname != ch.Hostname {
				continue
			}
		case ch.City != "":
			if r.Location != ch.City {
				continue
			}
		case ch.Country != "":
			if countryCode(r.Location) != ch.Country || !r.IncludeInCountry {
				continue
			}
		}
		cand = append(cand, r)
	}
	if len(cand) == 0 {
		return nil, errors.New("no active Mullvad server matches this choice")
	}
	total := 0
	for _, r := range cand {
		total += max(r.Weight, 1)
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(total)))
	if err != nil {
		return nil, err
	}
	x := int(n.Int64())
	for i := range cand {
		x -= max(cand[i].Weight, 1)
		if x < 0 {
			return &cand[i], nil
		}
	}
	return &cand[0], nil
}

// HopMTU is the MTU of a tunnel that runs through depth other tunnels: every
// WireGuard layer adds 80 bytes (IPv6 outer header), so the inner tunnel must
// be smaller or packets fragment.
func HopMTU(depth int) int {
	if depth <= 0 {
		return 0 // default (1420)
	}
	return max(1420-80*depth, 1280)
}

func randn(n int) int {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0
	}
	return int(v.Int64())
}

// PickChain chooses n relays for a chain: every hop in another country, and
// as far as the list allows at another hosting provider, so no single
// operator or country sees both ends. entry/exit are country codes ("" =
// any); the first relay is the entry, the last the exit.
func (l *RelayList) PickChain(n int, entry, exit string) ([]*Relay, error) {
	if n < 2 || n > 4 {
		return nil, errors.New("a chain has 2 to 4 hops")
	}
	byCC := map[string][]int{}
	for i, r := range l.WireGuard.Relays {
		if r.Active && r.IncludeInCountry {
			byCC[countryCode(r.Location)] = append(byCC[countryCode(r.Location)], i)
		}
	}
	if len(byCC) < n {
		return nil, errors.New("not enough countries with active servers")
	}
	for _, cc := range []string{entry, exit} {
		if cc != "" && len(byCC[cc]) == 0 {
			return nil, fmt.Errorf("no active Mullvad server in %q", cc)
		}
	}
	if entry != "" && entry == exit {
		return nil, errors.New("entry and exit must be in different countries")
	}
	var pool []string
	for cc := range byCC {
		if cc != entry && cc != exit {
			pool = append(pool, cc)
		}
	}
	sort.Strings(pool)
	ccs := make([]string, n)
	ccs[0], ccs[n-1] = entry, exit
	for i := range ccs {
		if ccs[i] != "" {
			continue
		}
		k := randn(len(pool))
		ccs[i] = pool[k]
		pool = append(pool[:k], pool[k+1:]...)
	}
	usedProv := map[string]bool{}
	out := make([]*Relay, 0, n)
	for _, cc := range ccs {
		var fresh, any []int
		for _, i := range byCC[cc] {
			any = append(any, i)
			if !usedProv[l.WireGuard.Relays[i].Provider] {
				fresh = append(fresh, i)
			}
		}
		src := any
		if len(fresh) > 0 {
			src = fresh
		}
		r := l.WireGuard.Relays[src[randn(len(src))]]
		usedProv[r.Provider] = true
		out = append(out, &r)
	}
	return out, nil
}

// Conf builds the wg-quick file for one relay (mtu 0 = default). Mullvad's resolver sits at
// the tunnel gateway; the tunnel takes all traffic (Shunt decides who uses it).
func Conf(priv string, dev *Device, r *Relay, gateway string, mtu int) (string, error) {
	if !hostRe.MatchString(r.Hostname) || strings.ContainsAny(priv+dev.IPv4+dev.IPv6+r.IPv4+r.PubKey, "\n\r ") {
		return "", errors.New("unexpected characters in the Mullvad data")
	}
	if gateway == "" {
		gateway = "10.64.0.1"
	}
	addr := dev.IPv4
	if dev.IPv6 != "" {
		addr += ", " + dev.IPv6
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Mullvad %s (made by Shunt; do not edit, use the Mullvad page)\n", r.Hostname)
	fmt.Fprintf(&b, "[Interface]\nPrivateKey = %s\nAddress = %s\nDNS = %s\n", priv, addr, gateway)
	if mtu > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", mtu)
	}
	b.WriteString("\n")
	fmt.Fprintf(&b, "[Peer]\nPublicKey = %s\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = %s:%d\nPersistentKeepalive = 25\n", r.PubKey, r.IPv4, Port)
	return b.String(), nil
}
