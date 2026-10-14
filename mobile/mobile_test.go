//go:build linux

package mobile

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// status as JSON (splitstack's status)
type tunnelStatus struct {
	Name      string `json:"name"`
	Up        bool   `json:"up"`
	Error     string `json:"error"`
	Handshake int64  `json:"handshake"`
	RX        int64  `json:"rx"`
}

type status struct {
	Tunnels    []tunnelStatus `json:"tunnels"`
	Blocked    int64          `json:"blocked"`
	DNSBlocked int64          `json:"dns_blocked"`
}

type fakePlatform struct{ uid atomic.Int64 }

func (p *fakePlatform) OwnerUid(int, string, int, string, int) int { return int(p.uid.Load()) }
func (p *fakePlatform) Log(string)                                 {}

var serverIP = netip.MustParseAddr("10.9.0.1")

// wgServer runs a WireGuard peer on 127.0.0.1 with a TCP echo on :80 and a
// UDP echo on :53 inside its tunnel network.
func wgServer(t *testing.T, clientPub wgtypes.Key, tag string) (pub wgtypes.Key, port int) {
	t.Helper()
	priv, _ := wgtypes.GeneratePrivateKey()
	tdev, tnet, err := netstack.CreateNetTUN([]netip.Addr{serverIP}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	pc, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	port = pc.LocalAddr().(*net.UDPAddr).Port
	pc.Close()
	uapi := fmt.Sprintf("private_key=%x\nlisten_port=%d\npublic_key=%x\nallowed_ip=10.9.0.2/32\n", priv[:], port, clientPub[:])
	if err := dev.IpcSet(uapi); err != nil {
		t.Fatal(err)
	}
	dev.Up()
	t.Cleanup(dev.Close)
	l, err := tnet.ListenTCPAddrPort(netip.AddrPortFrom(serverIP, 80))
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	u, err := tnet.ListenUDPAddrPort(netip.AddrPortFrom(serverIP, 53))
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, a, err := u.ReadFrom(buf)
			if err != nil {
				return
			}
			u.WriteTo(append([]byte(tag+":"), buf[:n]...), a)
		}
	}()
	return priv.PublicKey(), port
}

// appStack is the phone's side of the TUN: the apps.
func appStack(t *testing.T, fd int) *stack.Stack {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	ep, err := fdbased.New(&fdbased.Options{FDs: []int{fd}, MTU: 1280, PacketDispatchMode: fdbased.Readv})
	if err != nil {
		t.Fatal(err)
	}
	s.CreateNIC(1, ep)
	s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFrom4([4]byte{10, 111, 0, 2}).WithPrefix()}, stack.AddressProperties{})
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	t.Cleanup(func() { s.Close() })
	return s
}

func full(a netip.AddrPort) tcpip.FullAddress {
	return tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(a.Addr().As4()), Port: a.Port()}
}

func echoTCP(s *stack.Stack, dst netip.AddrPort) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := gonet.DialContextTCP(ctx, s, full(dst), ipv4.ProtocolNumber)
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte("hello")); err != nil {
		return err
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(c, buf); err != nil {
		return err
	}
	if string(buf) != "hello" {
		return fmt.Errorf("got %q", buf)
	}
	return nil
}

func udpQuery(s *stack.Stack, dst netip.AddrPort) (string, error) {
	c, err := gonet.DialUDP(s, nil, &tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(dst.Addr().As4()), Port: dst.Port()}, ipv4.ProtocolNumber)
	if err != nil {
		return "", err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	c.Write([]byte("q"))
	buf := make([]byte, 100)
	n, err := c.Read(buf)
	return string(buf[:n]), err
}

func TestRoutes(t *testing.T) {
	cpriv, _ := wgtypes.GeneratePrivateKey()
	spub, port := wgServer(t, cpriv.PublicKey(), "dns")
	b64 := func(k wgtypes.Key) string { return base64.StdEncoding.EncodeToString(k[:]) }
	conf := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.9.0.2/32\nDNS = 10.9.0.1\n\n[Peer]\nPublicKey = %s\nEndpoint = 127.0.0.1:%d\nAllowedIPs = 0.0.0.0/0\n",
		b64(cpriv), b64(spub), port)
	if _, err := CheckWireGuard(conf); err != nil {
		t.Fatal(err)
	}

	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatal(err)
	}
	cfg := func(def string, apps map[string]string) string {
		b, _ := json.Marshal(map[string]any{
			"tunnels": []map[string]string{{"name": "t1", "conf": conf}, {"name": "broken", "conf": "[Interface]\n"}},
			"default": def, "apps": apps, "direct_dns": "127.0.0.1",
		})
		return string(b)
	}
	p := &fakePlatform{}
	p.uid.Store(10001)
	e, err := Start(fds[0], cfg("tunnel:t1", nil), p)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Stop()
	app := appStack(t, fds[1])
	echo := netip.AddrPortFrom(serverIP, 80)

	// default route: through the tunnel
	if err := echoTCP(app, echo); err != nil {
		t.Fatalf("tcp through tunnel: %v", err)
	}
	// Wi-Fi <-> mobile data: sockets re-opened, tunnel keeps working
	e.NetworkChanged()
	if err := echoTCP(app, echo); err != nil {
		t.Fatalf("tcp after network change: %v", err)
	}
	// DNS to the VPN's DNS address goes to the tunnel's DNS server
	if got, err := udpQuery(app, netip.MustParseAddrPort(DNSAddr+":53")); err != nil || got != "dns:q" {
		t.Fatalf("dns through tunnel: %q %v", got, err)
	}
	// this app blocked, another one still tunneled
	if err := e.SetRules(cfg("tunnel:t1", map[string]string{"10001": "block"})); err != nil {
		t.Fatal(err)
	}
	if err := echoTCP(app, echo); err == nil {
		t.Fatal("blocked app got through")
	}
	if _, err := udpQuery(app, netip.MustParseAddrPort(DNSAddr+":53")); err == nil {
		t.Fatal("blocked app's DNS got an answer")
	}
	p.uid.Store(10002)
	if err := echoTCP(app, echo); err != nil {
		t.Fatalf("other app: %v", err)
	}
	// direct: the tunnel-only address is not reachable that way
	if err := e.SetRules(cfg("direct", nil)); err != nil {
		t.Fatal(err)
	}
	if err := echoTCP(app, echo); err == nil {
		t.Fatal("direct route reached a tunnel-only address")
	}
	// a broken tunnel blocks instead of leaking
	if err := e.SetRules(cfg("tunnel:broken", nil)); err != nil {
		t.Fatal(err)
	}
	if err := echoTCP(app, echo); err == nil {
		t.Fatal("broken tunnel let traffic through")
	}

	var st status
	json.Unmarshal([]byte(e.Status()), &st)
	var t1 tunnelStatus
	for _, x := range st.Tunnels {
		if x.Name == "t1" {
			t1 = x
		}
		if x.Name == "broken" && (x.Up || x.Error == "") {
			t.Errorf("broken tunnel status: %+v", x)
		}
	}
	if !t1.Up || t1.Handshake == 0 || t1.RX == 0 {
		t.Errorf("t1 status: %+v", t1)
	}
	if st.Blocked < 2 {
		t.Errorf("blocked = %d", st.Blocked)
	}
	if err := e.SetRules(cfg("tunnel:nope", nil)); err == nil || !strings.Contains(err.Error(), "unknown route") {
		t.Errorf("unknown tunnel accepted: %v", err)
	}
}

// Two WireGuard tunnels at the same time, chosen per app (UID).
func TestTwoTunnels(t *testing.T) {
	b64 := func(k wgtypes.Key) string { return base64.StdEncoding.EncodeToString(k[:]) }
	var tunnels []map[string]string
	for _, name := range []string{"home", "work"} {
		cpriv, _ := wgtypes.GeneratePrivateKey()
		spub, port := wgServer(t, cpriv.PublicKey(), name)
		tunnels = append(tunnels, map[string]string{"name": name, "conf": fmt.Sprintf(
			"[Interface]\nPrivateKey = %s\nAddress = 10.9.0.2/32\n\n[Peer]\nPublicKey = %s\nEndpoint = 127.0.0.1:%d\nAllowedIPs = 0.0.0.0/0\n", b64(cpriv), b64(spub), port)})
	}
	b, _ := json.Marshal(map[string]any{"tunnels": tunnels, "default": "block",
		"apps": map[string]string{"10001": "tunnel:home", "10002": "tunnel:work"}})
	fds, _ := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	p := &fakePlatform{}
	e, err := Start(fds[0], string(b), p)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Stop()
	app := appStack(t, fds[1])
	dst := netip.AddrPortFrom(serverIP, 53) // the same address in both tunnels
	for uid, want := range map[int64]string{10001: "home:q", 10002: "work:q"} {
		p.uid.Store(uid)
		if got, err := udpQuery(app, dst); err != nil || got != want {
			t.Errorf("uid %d: got %q (%v), want %q", uid, got, err, want)
		}
	}
	p.uid.Store(10003) // no rule: default block
	if got, err := udpQuery(app, dst); err == nil {
		t.Errorf("app without rule got %q", got)
	}
}

func TestDNSFilter(t *testing.T) {
	cpriv, _ := wgtypes.GeneratePrivateKey()
	spub, port := wgServer(t, cpriv.PublicKey(), "upstream")
	b64 := func(k wgtypes.Key) string { return base64.StdEncoding.EncodeToString(k[:]) }
	conf := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.9.0.2/32\nDNS = 10.9.0.1\n\n[Peer]\nPublicKey = %s\nEndpoint = 127.0.0.1:%d\nAllowedIPs = 0.0.0.0/0\n", b64(cpriv), b64(spub), port)
	list := t.TempDir() + "/ads.txt"
	os.WriteFile(list, []byte("0.0.0.0 tracker.example.net\n||ads.example.com^\n"), 0o644)
	b, _ := json.Marshal(map[string]any{"tunnels": []map[string]string{{"name": "t", "conf": conf}}, "default": "tunnel:t",
		"blocklists": []map[string]string{{"name": "ads", "path": list}}, "unfiltered": []string{"10002"}})
	fds, _ := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	p := &fakePlatform{}
	p.uid.Store(10001)
	e, err := Start(fds[0], string(b), p)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Stop()
	app := appStack(t, fds[1])
	ask := func(name string) (*dns.Msg, string) {
		q := new(dns.Msg)
		q.SetQuestion(name, dns.TypeA)
		raw, _ := q.Pack()
		c, err := gonet.DialUDP(app, nil, &tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{10, 111, 0, 53}), Port: 53}, ipv4.ProtocolNumber)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		c.Write(raw)
		buf := make([]byte, 1500)
		n, err := c.Read(buf)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var r dns.Msg
		if r.Unpack(buf[:n]) == nil && r.Response {
			return &r, ""
		}
		return nil, string(buf[:n]) // the test upstream echoes "upstream:<query>"
	}
	if r, _ := ask("ads.example.com."); r == nil || r.Rcode != dns.RcodeNameError {
		t.Errorf("blocked name not NXDOMAIN: %v", r)
	}
	if r, _ := ask("sub.ads.example.com."); r == nil || r.Rcode != dns.RcodeNameError {
		t.Errorf("subdomain of a blocked name not NXDOMAIN: %v", r)
	}
	if r, _ := ask("tracker.example.net."); r == nil || r.Rcode != dns.RcodeNameError {
		t.Errorf("hosts-file entry not NXDOMAIN: %v", r)
	}
	if _, echo := ask("cdn.tracker.example.net."); !strings.HasPrefix(echo, "upstream:") {
		t.Errorf("hosts-file entries block only the exact name, got %q", echo)
	}
	if _, echo := ask("example.org."); !strings.HasPrefix(echo, "upstream:") {
		t.Errorf("allowed name did not reach the upstream: %q", echo)
	}
	p.uid.Store(10002) // unfiltered app
	if _, echo := ask("ads.example.com."); !strings.HasPrefix(echo, "upstream:") {
		t.Errorf("unfiltered app was filtered")
	}
	var st status
	json.Unmarshal([]byte(e.Status()), &st)
	if st.DNSBlocked != 3 {
		t.Errorf("dns_blocked = %d, want 3", st.DNSBlocked)
	}
}
