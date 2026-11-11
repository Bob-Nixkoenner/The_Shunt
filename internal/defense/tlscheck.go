package defense

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// TLS certificate check: a few well-known public sites are contacted over the
// default route on joining a network and then every TLSInterval. What is
// remembered per target is the issuer of the top certificate of the chain
// (the CA that signed the last certificate the server sends, normally the
// root). CDNs rotate leaf certificates and often intermediates, so neither is
// compared. A different top issuer, a chain that the system roots do not
// verify, or two ways that disagree is a KindTLS event (severity high).
//
// Pinning: the first sight is only trusted in a network the user marked
// trusted, or when a second way (the name resolved over DoH, then dialled by
// address) shows the same chain. In public and managed networks a target
// with no pin and no second way is left alone. Only public sites are used;
// nothing personal is ever contacted.

// DefaultTLSTargets are used when defense.tls_targets is empty.
var DefaultTLSTargets = []string{"api.github.com", "www.wikipedia.org"}

// MaxTLSTargets limits defense.tls_targets.
const MaxTLSTargets = 16

// TLSInterval is the pause between two checks after the one on joining.
const TLSInterval = 6 * time.Hour

const maxPinsPerTarget = 8

// TLSTargets returns the configured targets, or the defaults.
func TLSTargets(cfg Config) []string {
	if len(cfg.TLSTargets) == 0 {
		return DefaultTLSTargets
	}
	return cfg.TLSTargets
}

// DialFunc opens a TCP connection (the daemon passes the default route's dialer).
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// FetchChain does a TLS handshake with addr, announcing serverName, and
// returns the certificates the server sent. Verification is left to the
// caller (it needs the chain even when it does not verify).
func FetchChain(ctx context.Context, dial DialFunc, addr, serverName string) ([]*x509.Certificate, error) {
	if dial == nil {
		dial = (&net.Dialer{Timeout: 10 * time.Second}).DialContext
	}
	conn, err := dial(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	tc := tls.Client(conn, &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12,
		InsecureSkipVerify: true}) // #nosec G402: the chain is verified by TLSChecker, which needs it even when it fails
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return tc.ConnectionState().PeerCertificates, nil
}

// chainIssuerFP is the remembered fingerprint: SHA-256 of the issuer name of
// the last certificate of the chain.
func chainIssuerFP(chain []*x509.Certificate) string {
	if len(chain) == 0 {
		return ""
	}
	h := sha256.Sum256(chain[len(chain)-1].RawIssuer)
	return hex.EncodeToString(h[:])
}

// verifyChain checks the chain against roots (nil = system roots) for host.
func verifyChain(chain []*x509.Certificate, host string, roots *x509.CertPool, now time.Time) error {
	if len(chain) == 0 {
		return fmt.Errorf("no certificate")
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	_, err := chain[0].Verify(x509.VerifyOptions{DNSName: host, Roots: roots, Intermediates: inter, CurrentTime: now})
	return err
}

// TLSChecker runs the check. Fetch is the normal way (default route, normal
// name resolution), FetchAlt the second way (nil = none). Path is the pin
// file (mode 0600; "" = memory only).
type TLSChecker struct {
	M        *Manager
	Path     string
	Roots    *x509.CertPool // nil = system roots
	Fetch    func(ctx context.Context, host string) ([]*x509.Certificate, error)
	FetchAlt func(ctx context.Context, host string) ([]*x509.Certificate, error)
	Now      func() time.Time

	mu     sync.Mutex
	pins   map[string][]string
	loaded bool
}

func (c *TLSChecker) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *TLSChecker) loadLocked() {
	if c.loaded {
		return
	}
	c.loaded = true
	c.pins = map[string][]string{}
	if c.Path == "" {
		return
	}
	if b, err := os.ReadFile(c.Path); err == nil {
		_ = json.Unmarshal(b, &c.pins)
	}
}

func (c *TLSChecker) saveLocked() {
	if c.Path == "" {
		return
	}
	b, err := json.Marshal(c.pins)
	if err != nil {
		return
	}
	if os.MkdirAll(filepath.Dir(c.Path), 0o700) != nil {
		return
	}
	tmp := c.Path + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, c.Path)
	}
}

// Pins returns the remembered fingerprints per target (a copy; for tests).
func (c *TLSChecker) Pins() map[string][]string {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.loadLocked()
	out := map[string][]string{}
	for k, v := range c.pins {
		out[k] = append([]string(nil), v...)
	}
	return out
}

// Run checks every target once. class is the current network's class.
// Targets that cannot be reached are skipped silently (no network is no finding).
func (c *TLSChecker) Run(ctx context.Context, targets []string, class Class) {
	if c.M == nil || !c.M.Watching(FeatTLS) {
		return
	}
	class = class.Normalize()
	sorted := append([]string(nil), targets...)
	sort.Strings(sorted)
	for _, host := range sorted {
		if ctx.Err() != nil {
			return
		}
		c.checkOne(ctx, host, class)
	}
}

func (c *TLSChecker) report(host, what string) {
	c.M.Report(Event{Kind: KindTLS, Severity: SevHigh, Proto: "tcp", Port: 443, Detail: "target=" + host + " " + what})
}

func (c *TLSChecker) checkOne(ctx context.Context, host string, class Class) {
	chain, err := c.Fetch(ctx, host)
	if err != nil || len(chain) == 0 {
		return
	}
	if err := verifyChain(chain, host, c.Roots, c.now()); err != nil {
		if class != ClassTrusted {
			c.report(host, "chain not trusted by the system roots")
		}
		return
	}
	fp := chainIssuerFP(chain)
	c.mu.Lock()
	c.loadLocked()
	pins := c.pins[host]
	c.mu.Unlock()
	known := false
	for _, p := range pins {
		if p == fp {
			known = true
		}
	}
	switch {
	case known:
		return
	case class == ClassTrusted:
		c.learn(host, fp) // the user trusts this network: a new issuer is learned, not reported
	case len(pins) > 0:
		c.report(host, "issuer chain differs from the remembered one")
	default:
		if c.FetchAlt == nil {
			return
		}
		alt, err := c.FetchAlt(ctx, host)
		if err != nil || len(alt) == 0 {
			return // no second way: nothing is pinned, nothing is claimed
		}
		if chainIssuerFP(alt) != fp {
			c.report(host, "two ways to the target show different issuers")
			return
		}
		c.learn(host, fp)
	}
}

func (c *TLSChecker) learn(host, fp string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.loadLocked()
	p := append(c.pins[host], fp)
	if len(p) > maxPinsPerTarget {
		p = p[len(p)-maxPinsPerTarget:]
	}
	c.pins[host] = p
	c.saveLocked()
}
