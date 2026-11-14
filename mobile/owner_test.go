//go:build linux

package mobile

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// flakyPlatform answers the next fail lookups with a miss (alternating
// "unknown" and "error"), then uid; uid < 0 misses for good.
type flakyPlatform struct {
	uid   atomic.Int64
	fail  atomic.Int64
	calls atomic.Int64
	mu    sync.Mutex
	logs  []string
}

func (p *flakyPlatform) OwnerUid(int, string, int, string, int) int {
	n := p.calls.Add(1)
	if p.fail.Add(-1) >= 0 || p.uid.Load() < 0 {
		if n%2 == 0 {
			return ownerErr
		}
		return -1
	}
	return int(p.uid.Load())
}
func (p *flakyPlatform) Log(m string) { p.mu.Lock(); p.logs = append(p.logs, m); p.mu.Unlock() }
func (p *flakyPlatform) AppName(int) string {
	return ""
}

// hostEcho is a TCP echo on an address of this machine that the direct
// route reaches (loopback would not leave the apps' netstack).
func hostEcho(t *testing.T) netip.AddrPort {
	var ip netip.Addr
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil && p.Addr().Is4() && !p.Addr().IsLoopback() {
			ip = p.Addr()
			break
		}
	}
	if !ip.IsValid() {
		t.Skip("no non-loopback IPv4 address")
	}
	l, err := net.Listen("tcp4", net.JoinHostPort(ip.String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	return netip.MustParseAddrPort(l.Addr().String())
}

// A lookup that misses twice and then finds the owner gets the app's
// route; one that never finds it gets the default, or is dropped with
// owner_unknown "drop".
func TestOwnerRetryAndUnknown(t *testing.T) {
	direct := hostEcho(t)
	cpriv, _ := wgtypes.GeneratePrivateKey()
	spub, port := wgServer(t, cpriv.PublicKey(), "dns")
	b64 := func(k wgtypes.Key) string { return base64.StdEncoding.EncodeToString(k[:]) }
	conf := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.9.0.2/32\nDNS = 10.9.0.1\n\n[Peer]\nPublicKey = %s\nEndpoint = 127.0.0.1:%d\nAllowedIPs = 0.0.0.0/0\n",
		b64(cpriv), b64(spub), port)
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatal(err)
	}
	cfg := func(unknown string) string {
		b, _ := json.Marshal(map[string]any{
			"tunnels": []map[string]string{{"name": "t1", "conf": conf}},
			"default": "direct", "apps": map[string]string{"10001": "tunnel:t1"},
			"direct_dns": "127.0.0.1", "owner_unknown": unknown,
		})
		return string(b)
	}
	p := &flakyPlatform{}
	p.uid.Store(10001)
	e, err := Start(fds[0], cfg(""), p)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Stop()
	app := appStack(t, fds[1])
	tunnelOnly := netip.AddrPortFrom(serverIP, 80)
	blocked := func() int64 {
		var st status
		json.Unmarshal([]byte(e.Status()), &st)
		return st.Blocked
	}

	// two misses, then the owner: the app's tunnel (direct cannot reach it)
	p.fail.Store(2)
	p.calls.Store(0)
	if err := echoTCP(app, tunnelOnly); err != nil {
		t.Fatalf("tcp after two misses: %v", err)
	}
	if n := p.calls.Load(); n != 3 {
		t.Errorf("tcp: %d lookups, want 3", n)
	}
	// UDP too (its lookup runs off the TUN reader): DNS of the tunnel
	p.fail.Store(2)
	if got, err := udpQuery(app, netip.MustParseAddrPort(DNSAddr+":53")); err != nil || got != "dns:q" {
		t.Fatalf("udp after two misses: %q %v", got, err)
	}

	// never found, owner_unknown default: the default route (direct)
	p.uid.Store(-1)
	p.calls.Store(0)
	if err := echoTCP(app, direct); err != nil {
		t.Fatalf("unknown owner, default route: %v", err)
	}
	if n := p.calls.Load(); n != ownerTries {
		t.Errorf("unknown owner: %d lookups, want %d", n, ownerTries)
	}

	// owner_unknown drop: blocked (RST at once), known owners unchanged
	if err := e.SetRules(cfg("drop")); err != nil {
		t.Fatal(err)
	}
	b0 := blocked()
	if err := echoTCP(app, direct); err == nil {
		t.Fatal("unknown owner got through with owner_unknown drop")
	}
	if blocked() != b0+1 {
		t.Errorf("blocked %d -> %d", b0, blocked())
	}
	p.uid.Store(10002) // no rule: still the default
	if err := echoTCP(app, direct); err != nil {
		t.Fatalf("known owner without rule under drop: %v", err)
	}
	p.uid.Store(10001)
	if err := echoTCP(app, tunnelOnly); err != nil {
		t.Fatalf("known owner with rule under drop: %v", err)
	}

	if err := e.SetRules(cfg("bogus")); err == nil {
		t.Error("owner_unknown bogus accepted")
	}

	// misses are logged as counts only, without addresses or ports
	p.mu.Lock()
	defer p.mu.Unlock()
	seen := false
	for _, l := range p.logs {
		if !strings.HasPrefix(l, "owner lookup:") {
			continue
		}
		seen = true
		for _, leak := range []string{"10.111.", "10.9.", direct.Addr().String(), "10001"} {
			if strings.Contains(l, leak) {
				t.Errorf("owner log names %q: %q", leak, l)
			}
		}
	}
	if !seen {
		t.Errorf("no owner lookup log: %q", p.logs)
	}
}

// The log line is rate limited and carries the counts.
func TestOwnerLookupLog(t *testing.T) {
	p := &flakyPlatform{}
	p.uid.Store(-1)
	var logs []string
	l := &ownerLookup{p: p, log: func(m string) { logs = append(logs, m) }}
	src, dst := netip.MustParseAddrPort("10.111.0.2:40000"), netip.MustParseAddrPort("192.0.2.1:443")
	for range 5 {
		if got := l.owner(6, src, dst); got != "" {
			t.Fatalf("owner %q, want unknown", got)
		}
	}
	if len(logs) != 1 || !strings.Contains(logs[0], "1 connections without owner") {
		t.Fatalf("logs: %q", logs)
	}
	if l.unknown != 4 || l.errs+l.nouid != 4*ownerTries {
		t.Errorf("pending counts: unknown %d, misses %d", l.unknown, l.errs+l.nouid)
	}
	p.uid.Store(7)
	p.fail.Store(1)
	if got := l.owner(17, src, dst); got != "7" || l.late != 1 {
		t.Errorf("retry: owner %q, late %d", got, l.late)
	}
}
