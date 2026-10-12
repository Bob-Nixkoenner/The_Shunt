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
	"os"
	"strings"
	"sync"
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

// SystemUpstreams returns the system's resolvers as plain UDP upstreams.
// Loopback stubs are skipped: their own upstream queries would be
// redirected back to us (loop). If /etc/resolv.conf only points to the
// systemd-resolved stub, resolved's real upstreams are used instead.
func SystemUpstreams() []config.UpstreamSpec {
	var out []config.UpstreamSpec
	for _, f := range resolvConfFiles {
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

// SystemUpstream forwards to the system's resolvers and follows changes:
// at boot shuntd may start before NetworkManager has written resolv.conf,
// and laptops change networks (and resolvers) all the time.
type SystemUpstream struct {
	mark uint32

	mu    sync.Mutex
	stamp string
	specs []config.UpstreamSpec
	ups   []Upstream
}

// NewSystemUpstream creates a system resolver upstream using the given mark.
func NewSystemUpstream(mark uint32) *SystemUpstream { return &SystemUpstream{mark: mark} }

var resolvConfFiles = []string{"/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"}

func (s *SystemUpstream) current() ([]config.UpstreamSpec, []Upstream) {
	var stamp strings.Builder
	for _, f := range resolvConfFiles {
		if st, err := os.Stat(f); err == nil {
			fmt.Fprintf(&stamp, "%s:%d:%d;", f, st.ModTime().UnixNano(), st.Size())
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if stamp.String() != s.stamp || len(s.ups) == 0 {
		s.stamp = stamp.String()
		s.specs = SystemUpstreams()
		s.ups = s.ups[:0]
		for _, sp := range s.specs {
			s.ups = append(s.ups, NewUpstream(sp, s.mark))
		}
	}
	return s.specs, s.ups
}

// Servers lists the resolvers currently in use.
func (s *SystemUpstream) Servers() []config.UpstreamSpec {
	specs, _ := s.current()
	return specs
}

// Exchange implements Upstream, trying each system resolver in turn.
func (s *SystemUpstream) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	_, ups := s.current()
	if len(ups) == 0 {
		return nil, fmt.Errorf("no system resolver (resolv.conf lists only loopback stubs or nothing)")
	}
	var err error
	for _, u := range ups {
		var r *dns.Msg
		if r, err = u.Exchange(ctx, m); err == nil {
			return r, nil
		}
	}
	return nil, err
}

func (s *SystemUpstream) String() string {
	specs, _ := s.current()
	names := make([]string, len(specs))
	for i, sp := range specs {
		names[i] = sp.Proto + "://" + sp.Addr.String()
	}
	if len(names) == 0 {
		return "system (none found yet)"
	}
	return "system (" + strings.Join(names, ", ") + ")"
}

// PushedUpstream forwards to DNS servers that are only known at run time,
// like the ones an OpenVPN server pushes when it connects.
type PushedUpstream struct {
	mark    uint32
	servers func() []netip.Addr
}

// NewPushedUpstream creates an upstream asking servers() for the current
// resolvers (plain DNS on port 53, sent with mark).
func NewPushedUpstream(mark uint32, servers func() []netip.Addr) *PushedUpstream {
	return &PushedUpstream{mark: mark, servers: servers}
}

func (p *PushedUpstream) ups() []Upstream {
	var out []Upstream
	for _, a := range p.servers() {
		out = append(out, NewUpstream(config.UpstreamSpec{Proto: "udp", Addr: netip.AddrPortFrom(a, 53)}, p.mark))
	}
	return out
}

// Exchange implements Upstream.
func (p *PushedUpstream) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	ups := p.ups()
	if len(ups) == 0 {
		return nil, fmt.Errorf("no DNS server pushed by the VPN server (yet)")
	}
	var err error
	for _, u := range ups {
		var r *dns.Msg
		if r, err = u.Exchange(ctx, m); err == nil {
			return r, nil
		}
	}
	return nil, err
}

func (p *PushedUpstream) String() string {
	var names []string
	for _, a := range p.servers() {
		names = append(names, "udp://"+netip.AddrPortFrom(a, 53).String())
	}
	return "pushed (" + strings.Join(names, ", ") + ")"
}
