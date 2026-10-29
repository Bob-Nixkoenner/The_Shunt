package splitstack

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/socks"
)

// torResolver answers the stack's DNS queries without Tor's DNSPort: it asks
// the SOCKS port to resolve (Tor's RESOLVE command). Orbot (17.x) opens its
// DNSPort on a random port ("DNSPort auto"), so a fixed port cannot be used.
// A queries get the address Tor returns; AAAA and other types an empty
// answer; a name Tor cannot resolve gets NXDOMAIN (never an answer from
// somewhere else).
type torResolver struct {
	socks string
	mu    sync.Mutex
	out   chan []byte
	done  chan struct{}
	once  sync.Once
	rd    time.Time
}

func newTorResolver(socks string) *torResolver {
	return &torResolver{socks: socks, out: make(chan []byte, 16), done: make(chan struct{})}
}

type dnsQ struct {
	id    []byte
	name  string
	qtype uint16
	end   int // end of the question section
}

func parseDNSQuestion(p []byte) (dnsQ, bool) {
	if len(p) < 17 || p[2]&0x80 != 0 || p[4] != 0 || p[5] != 1 {
		return dnsQ{}, false
	}
	var labels []string
	i := 12
	for {
		if i >= len(p) {
			return dnsQ{}, false
		}
		l := int(p[i])
		if l == 0 {
			i++
			break
		}
		if l&0xC0 != 0 || i+1+l > len(p) {
			return dnsQ{}, false
		}
		labels = append(labels, string(p[i+1:i+1+l]))
		i += 1 + l
	}
	if i+4 > len(p) {
		return dnsQ{}, false
	}
	return dnsQ{id: p[:2], name: strings.Join(labels, "."), qtype: uint16(p[i])<<8 | uint16(p[i+1]), end: i + 4}, true
}

// dnsReply builds the answer to the query p (rcode 0 = ok, 3 = NXDOMAIN, 2 = SERVFAIL).
func dnsReply(p []byte, q dnsQ, rcode byte, ip netip.Addr) []byte {
	r := append([]byte{}, p[:q.end]...)
	r[2] = 0x81 | (p[2] & 0x01)
	r[3] = 0x80 | rcode
	r[6], r[7], r[8], r[9], r[10], r[11] = 0, 0, 0, 0, 0, 0
	if rcode == 0 && ip.IsValid() && ((q.qtype == 1 && ip.Is4()) || (q.qtype == 28 && ip.Is6())) {
		r[7] = 1
		r = append(r, 0xC0, 0x0C, byte(q.qtype>>8), byte(q.qtype), 0, 1, 0, 0, 0, 30, 0, byte(len(ip.AsSlice())))
		r = append(r, ip.AsSlice()...)
	}
	return r
}

func (r *torResolver) Write(p []byte) (int, error) {
	q, ok := parseDNSQuestion(p)
	if !ok {
		return len(p), nil
	}
	query := append([]byte{}, p...)
	go func() {
		var resp []byte
		switch {
		case q.qtype != 1 && q.qtype != 28:
			resp = dnsReply(query, q, 0, netip.Addr{})
		case q.qtype == 28 && !strings.HasSuffix(q.name, ".onion"):
			resp = dnsReply(query, q, 0, netip.Addr{}) // Tor RESOLVE gives IPv4 first; AAAA stays empty
		default:
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			ip, err := socks.Resolve(ctx, r.socks, torUser, q.name)
			switch {
			case err == nil:
				resp = dnsReply(query, q, 0, ip)
			case errors.As(err, new(*socks.ReplyError)):
				resp = dnsReply(query, q, 3, netip.Addr{})
			default:
				resp = dnsReply(query, q, 2, netip.Addr{})
			}
		}
		select {
		case r.out <- resp:
		case <-r.done:
		}
	}()
	return len(p), nil
}

func (r *torResolver) Read(b []byte) (int, error) {
	r.mu.Lock()
	dl := r.rd
	r.mu.Unlock()
	var tc <-chan time.Time
	if !dl.IsZero() {
		t := time.NewTimer(time.Until(dl))
		defer t.Stop()
		tc = t.C
	}
	select {
	case m := <-r.out:
		return copy(b, m), nil
	case <-r.done:
		return 0, net.ErrClosed
	case <-tc:
		return 0, timeoutErr{}
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func (r *torResolver) Close() error         { r.once.Do(func() { close(r.done) }); return nil }
func (r *torResolver) LocalAddr() net.Addr  { return &net.UDPAddr{} }
func (r *torResolver) RemoteAddr() net.Addr { return &net.UDPAddr{} }
func (r *torResolver) SetDeadline(t time.Time) error {
	return r.SetReadDeadline(t)
}
func (r *torResolver) SetReadDeadline(t time.Time) error {
	r.mu.Lock()
	r.rd = t
	r.mu.Unlock()
	return nil
}
func (r *torResolver) SetWriteDeadline(time.Time) error { return nil }
