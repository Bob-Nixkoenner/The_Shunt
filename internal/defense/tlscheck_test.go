package defense

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newTestCA(t *testing.T, name string) *testCA {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	p := x509.NewCertPool()
	p.AddCert(c)
	return &testCA{c, k, p}
}

// serve starts a TLS server for host whose leaf is signed by ca; the chain it
// sends is leaf + ca certificate.
func (ca *testCA) serve(t *testing.T, host string) string {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: host},
		DNSNames: []string{host}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(12 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, &k.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der, ca.cert.Raw}, PrivateKey: k}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String()
}

func checkerFor(t *testing.T, m *Manager, roots *x509.CertPool, addr func() string, alt func() string) *TLSChecker {
	c := &TLSChecker{M: m, Path: filepath.Join(t.TempDir(), "p", "tlspins.json"), Roots: roots}
	c.Fetch = func(ctx context.Context, host string) ([]*x509.Certificate, error) {
		return FetchChain(ctx, nil, addr(), host)
	}
	if alt != nil {
		c.FetchAlt = func(ctx context.Context, host string) ([]*x509.Certificate, error) {
			a := alt()
			if a == "" {
				return nil, errors.New("no second way")
			}
			return FetchChain(ctx, nil, a, host)
		}
	}
	return c
}

func TestTLSCheckPinAndChange(t *testing.T) {
	const host = "svc.example.test"
	caA, caB := newTestCA(t, "Test Root A"), newTestCA(t, "Test Root B")
	addrA := caA.serve(t, host)
	// the "attacker" presents a chain from another root (trusted by the pool for this test,
	// so the issuer comparison, not the verification, is what fires)
	both := x509.NewCertPool()
	both.AddCert(caA.cert)
	both.AddCert(caB.cert)
	addrB := caB.serve(t, host)

	m, _ := enabledManager(t)
	cur := addrA
	c := checkerFor(t, m, both, func() string { return cur }, func() string { return addrA })
	ctx := context.Background()

	// public network, no pin, second way agrees: pinned, no event
	c.Run(ctx, []string{host}, ClassPublic)
	if n, _ := countKind(m, KindTLS); n != 0 || len(c.Pins()[host]) != 1 {
		t.Fatalf("first sight: events=%d pins=%v", n, c.Pins())
	}
	// same issuer again (new leaf): quiet
	c.Run(ctx, []string{host}, ClassPublic)
	if n, _ := countKind(m, KindTLS); n != 0 {
		t.Fatal("same issuer reported")
	}
	// issuer chain changes: high
	cur = addrB
	c.Run(ctx, []string{host}, ClassPublic)
	n, ev := countKind(m, KindTLS)
	if n != 1 || ev.Severity != SevHigh || ev.Detail != "target="+host+" issuer chain differs from the remembered one" {
		t.Fatalf("n=%d ev=%+v", n, ev)
	}
	if len(c.Pins()[host]) != 1 {
		t.Fatal("a changed chain must not be learned in a public network")
	}
	// pins persisted, file 0600
	st, err := os.Stat(c.Path)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("pin file %v %v", st, err)
	}
	// in a trusted network the new issuer is learned quietly
	c.Run(ctx, []string{host}, ClassTrusted)
	if n, _ := countKind(m, KindTLS); n != 1 || len(c.Pins()[host]) != 2 {
		t.Fatalf("trusted: events=%d pins=%v", n, c.Pins())
	}
	// and then it is known in public networks too
	c.Run(ctx, []string{host}, ClassPublic)
	if n, _ := countKind(m, KindTLS); n != 1 {
		t.Fatal("learned issuer reported")
	}
}

func TestTLSCheckSecondWayAndUntrusted(t *testing.T) {
	const host = "svc.example.test"
	caA, caB := newTestCA(t, "Test Root A"), newTestCA(t, "Test Root B")
	addrA, addrB := caA.serve(t, host), caB.serve(t, host)
	both := x509.NewCertPool()
	both.AddCert(caA.cert)
	both.AddCert(caB.cert)
	ctx := context.Background()

	// the two ways disagree: event, nothing pinned
	m, _ := enabledManager(t)
	c := checkerFor(t, m, both, func() string { return addrA }, func() string { return addrB })
	c.Run(ctx, []string{host}, ClassPublic)
	n, ev := countKind(m, KindTLS)
	if n != 1 || ev.Detail != "target="+host+" two ways to the target show different issuers" || len(c.Pins()) != 0 {
		t.Fatalf("n=%d %+v pins=%v", n, ev, c.Pins())
	}
	// no second way: silent, not pinned
	m2, _ := enabledManager(t)
	c2 := checkerFor(t, m2, both, func() string { return addrA }, nil)
	c2.Run(ctx, []string{host}, ClassPublic)
	if n, _ := countKind(m2, KindTLS); n != 0 || len(c2.Pins()) != 0 {
		t.Fatal("no second way must stay silent")
	}
	// second way fails (error): silent
	m3, _ := enabledManager(t)
	c3 := checkerFor(t, m3, both, func() string { return addrA }, func() string { return "" })
	c3.Run(ctx, []string{host}, ClassPublic)
	if n, _ := countKind(m3, KindTLS); n != 0 {
		t.Fatal("failed second way must stay silent")
	}
	// a chain the roots do not verify (unknown CA): high in public, quiet in trusted
	m4, _ := enabledManager(t)
	c4 := checkerFor(t, m4, caA.pool, func() string { return addrB }, nil)
	c4.Run(ctx, []string{host}, ClassTrusted)
	if n, _ := countKind(m4, KindTLS); n != 0 {
		t.Fatal("trusted network must stay quiet")
	}
	c4.Run(ctx, []string{host}, ClassPublic)
	if n, ev := countKind(m4, KindTLS); n != 1 || ev.Detail != "target="+host+" chain not trusted by the system roots" {
		t.Fatalf("untrusted: n=%d %+v", n, ev)
	}
	// unreachable target: nothing
	c5 := checkerFor(t, m4, caA.pool, func() string { return "127.0.0.1:1" }, nil)
	c5.Run(ctx, []string{host}, ClassPublic)
	if n, _ := countKind(m4, KindTLS); n != 1 {
		t.Fatal("unreachable target produced an event")
	}
}

func TestTLSCheckFeatureOffAndTargets(t *testing.T) {
	m, _ := enabledManager(t, func(c *Config) { c.Features[FeatTLS] = Feature{} })
	called := false
	c := &TLSChecker{M: m, Fetch: func(context.Context, string) ([]*x509.Certificate, error) { called = true; return nil, errors.New("x") }}
	c.Run(context.Background(), []string{"a.example.test"}, ClassPublic)
	if called {
		t.Fatal("feature off must not connect")
	}
	if got := TLSTargets(Config{}); len(got) != 2 || got[0] != "api.github.com" {
		t.Fatalf("defaults %v", got)
	}
	if got := TLSTargets(Config{TLSTargets: []string{"x.example.test"}}); len(got) != 1 {
		t.Fatalf("custom %v", got)
	}
}
