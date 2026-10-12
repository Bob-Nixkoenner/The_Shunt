package dnsproxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sys/unix"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
)

// Upstream forwards a query to one DNS server.
type Upstream interface {
	Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error)
	String() string
}

// markControl sets SO_MARK so the query takes the route's routing table:
// a tunnel's upstream is only reachable through that tunnel, and if the
// tunnel is down the query fails instead of leaking.
func markControl(mark uint32) func(string, string, syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark))
		})
		if err != nil {
			return err
		}
		return serr
	}
}

const upstreamTimeout = 4 * time.Second

// NewUpstream builds an upstream that sends its packets with the given mark.
func NewUpstream(spec config.UpstreamSpec, mark uint32) Upstream {
	dialer := &net.Dialer{Timeout: upstreamTimeout, Control: markControl(mark)}
	switch spec.Proto {
	case "https":
		return &dohUpstream{spec: spec, client: &http.Client{
			Timeout: upstreamTimeout,
			Transport: &http.Transport{
				DialContext:       dialer.DialContext,
				TLSClientConfig:   &tls.Config{ServerName: spec.TLSName, MinVersion: tls.VersionTLS12},
				ForceAttemptHTTP2: true,
				IdleConnTimeout:   30 * time.Second,
			},
		}}
	case "tls":
		return &classicUpstream{spec: spec, client: &dns.Client{
			Net: "tcp-tls", Dialer: dialer, Timeout: upstreamTimeout,
			TLSConfig: &tls.Config{ServerName: spec.TLSName, MinVersion: tls.VersionTLS12},
		}}
	default:
		u := &classicUpstream{spec: spec, client: &dns.Client{Net: spec.Proto, Dialer: dialer, Timeout: upstreamTimeout}}
		if spec.Proto == "udp" {
			u.tcp = &dns.Client{Net: "tcp", Dialer: dialer, Timeout: upstreamTimeout}
		}
		return u
	}
}

type classicUpstream struct {
	spec   config.UpstreamSpec
	client *dns.Client
	tcp    *dns.Client // retry for truncated UDP answers
}

func (u *classicUpstream) String() string { return u.spec.Proto + "://" + u.spec.Addr.String() }

func (u *classicUpstream) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	r, _, err := u.client.ExchangeContext(ctx, m, u.spec.Addr.String())
	if err == nil && r.Truncated && u.tcp != nil {
		r, _, err = u.tcp.ExchangeContext(ctx, m, u.spec.Addr.String())
	}
	return r, err
}

type dohUpstream struct {
	spec   config.UpstreamSpec
	client *http.Client
}

func (u *dohUpstream) String() string {
	return fmt.Sprintf("https://%s%s (%s)", u.spec.Addr, u.spec.Path, u.spec.TLSName)
}

// Exchange implements RFC 8484 (POST, application/dns-message).
func (u *dohUpstream) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	q := m.Copy()
	q.Id = 0 // RFC 8484 §4.1: cache friendly
	wire, err := q.Pack()
	if err != nil {
		return nil, err
	}
	host := u.spec.Addr.Addr().String()
	if u.spec.Addr.Addr().Is6() {
		host = "[" + host + "]"
	}
	url := fmt.Sprintf("https://%s:%d%s", host, u.spec.Addr.Port(), u.spec.Path)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Host = u.spec.TLSName
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh: http %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return nil, err
	}
	r := new(dns.Msg)
	if err := r.Unpack(body); err != nil {
		return nil, err
	}
	r.Id = m.Id
	return r, nil
}

// SystemUpstreams returns the resolvers the system used before Shunt, as
// plain UDP upstreams. Loopback stubs are skipped: their own upstream
// queries would be redirected back to us (loop). systemd-resolved's real
// upstreams are read from its non-stub resolv.conf.
func SystemUpstreams() []config.UpstreamSpec {
	var out []config.UpstreamSpec
	for _, f := range []string{"/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"} {
		cc, err := dns.ClientConfigFromFile(f)
		if err != nil {
			continue
		}
		for _, s := range cc.Servers {
			a, err := netip.ParseAddr(s)
			if err != nil || a.IsLoopback() {
				continue
			}
			out = append(out, config.UpstreamSpec{Proto: "udp", Addr: netip.AddrPortFrom(a.Unmap(), 53)})
		}
		if len(out) > 0 {
			return out
		}
	}
	return nil
}
