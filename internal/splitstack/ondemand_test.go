package splitstack

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// wgDNSServer runs a WireGuard peer on 127.0.0.1 whose :53 answers every A
// query with 192.0.2.<id>; it returns the client's config.
func wgDNSServer(t *testing.T, id byte, dnsLine string) string {
	t.Helper()
	spriv, _ := wgtypes.GeneratePrivateKey()
	cpriv, _ := wgtypes.GeneratePrivateKey()
	stun, snet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.9.0.1"), netip.MustParseAddr("10.9.0.2")}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	sdev := device.NewDevice(stun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	pc, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	port := pc.LocalAddr().(*net.UDPAddr).Port
	pc.Close()
	cpub := cpriv.PublicKey()
	sdev.IpcSet(fmt.Sprintf("private_key=%x\nlisten_port=%d\npublic_key=%x\nallowed_ip=10.9.0.3/32\n", spriv[:], port, cpub[:]))
	sdev.Up()
	t.Cleanup(sdev.Close)
	// 10.9.0.1 answers; 10.9.0.2 (a "dead" DNS server) is up but silent
	u, _ := snet.ListenUDPAddrPort(netip.MustParseAddrPort("10.9.0.1:53"))
	go dns.ActivateAndServe(nil, u, dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		r := new(dns.Msg)
		r.SetReply(q)
		r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, id)}}
		w.WriteMsg(r)
	}))
	silent, _ := snet.ListenUDPAddrPort(netip.MustParseAddrPort("10.9.0.2:53"))
	go func() {
		buf := make([]byte, 1500)
		for {
			if _, _, err := silent.ReadFrom(buf); err != nil {
				return
			}
		}
	}()
	b64 := func(k wgtypes.Key) string { return base64.StdEncoding.EncodeToString(k[:]) }
	spub := spriv.PublicKey()
	return fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.9.0.3/32\n%s\n[Peer]\nPublicKey = %s\nEndpoint = 127.0.0.1:%d\nAllowedIPs = 0.0.0.0/0\n",
		b64(cpriv), dnsLine, b64(spub), port)
}

// resolve asks the VPN's DNS address from the app side.
func resolve(apps *netstack.Net, name string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	c, err := apps.DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(netip.MustParseAddr(DNSAddr), 53))
	if err != nil {
		return "", err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(8 * time.Second))
	_ = ctx
	q := new(dns.Msg)
	q.SetQuestion(name, dns.TypeA)
	b, _ := q.Pack()
	c.Write(b)
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil {
		return "", err
	}
	var r dns.Msg
	if err := r.Unpack(buf[:n]); err != nil {
		return "", err
	}
	if len(r.Answer) == 0 {
		return fmt.Sprintf("rcode %d", r.Rcode), nil
	}
	return r.Answer[0].(*dns.A).A.String(), nil
}

func tunnelState(e *Engine, name string) (up, idle bool) {
	var st struct {
		Tunnels []struct {
			Name string `json:"name"`
			Up   bool   `json:"up"`
			Idle bool   `json:"idle"`
		} `json:"tunnels"`
	}
	json.Unmarshal([]byte(e.Status()), &st)
	for _, t := range st.Tunnels {
		if t.Name == name {
			return t.Up, t.Idle
		}
	}
	return false, false
}

func newTestEngine(t *testing.T, cfg map[string]any) (*Engine, *netstack.Net) {
	t.Helper()
	b, _ := json.Marshal(cfg)
	appDev, apps, _ := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.111.0.2")}, nil, 1280)
	link, stop := TunLink(appDev, 1280)
	t.Cleanup(func() { appDev.Close(); stop() })
	e, err := New(Options{Link: link, HealthEvery: 50 * time.Millisecond}, string(b))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Stop)
	return e, apps
}

func TestOnDemandTunnel(t *testing.T) {
	old := idleAfter
	idleAfter = 400 * time.Millisecond
	defer func() { idleAfter = old }()
	a := wgDNSServer(t, 1, "DNS = 10.9.0.1\n")
	b := wgDNSServer(t, 2, "DNS = 10.9.0.1\n")
	e, apps := newTestEngine(t, map[string]any{
		"tunnels":   []map[string]string{{"name": "a", "conf": a}, {"name": "b", "conf": b}},
		"default":   "tunnel:a",
		"on_demand": true,
	})
	for _, n := range []string{"a", "b"} {
		if up, idle := tunnelState(e, n); up || !idle {
			t.Fatalf("%s at start: up=%v idle=%v, want asleep", n, up, idle)
		}
	}
	if got, err := resolve(apps, "x.test."); err != nil || got != "192.0.2.1" {
		t.Fatalf("first query: %q %v", got, err)
	}
	if up, _ := tunnelState(e, "a"); !up {
		t.Error("a not awake after its first connection")
	}
	if up, idle := tunnelState(e, "b"); up || !idle {
		t.Error("b woke up although no app uses it")
	}
	// nobody uses a: it goes back to sleep
	deadline := time.Now().Add(5 * time.Second)
	for up, _ := tunnelState(e, "a"); up && time.Now().Before(deadline); up, _ = tunnelState(e, "a") {
		time.Sleep(50 * time.Millisecond)
	}
	if up, idle := tunnelState(e, "a"); up || !idle {
		t.Fatalf("a did not go to sleep: up=%v idle=%v", up, idle)
	}
	// and wakes again for the next query
	if got, err := resolve(apps, "y.test."); err != nil || got != "192.0.2.1" {
		t.Fatalf("query after sleep: %q %v", got, err)
	}
	// switched off live: everything wakes
	cfg, _ := json.Marshal(map[string]any{"tunnels": []map[string]string{{"name": "a", "conf": a}, {"name": "b", "conf": b}}, "default": "tunnel:a", "on_demand": false})
	if err := e.SetRules(string(cfg)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		if up, _ := tunnelState(e, "b"); up {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Error("b did not wake after on demand was turned off")
}

func TestOnDemandKeepsViaTunnel(t *testing.T) {
	a := wgDNSServer(t, 1, "DNS = 10.9.0.1\n")
	cfg := []tunnelConf{{Name: "a", Type: typeWireGuard}, {Name: "o", Type: typeOpenVPN, Via: "a"}, {Name: "c", Type: typeWireGuard}}
	_ = a
	if onDemandEligible(cfg[0], cfg) {
		t.Error("a carries an OpenVPN tunnel: it must stay up")
	}
	if onDemandEligible(cfg[1], cfg) {
		t.Error("OpenVPN tunnels do not sleep")
	}
	if !onDemandEligible(cfg[2], cfg) {
		t.Error("c may sleep")
	}
}

func TestDNSFallbackList(t *testing.T) {
	old := dnsRetryAfter
	dnsRetryAfter = 300 * time.Millisecond
	defer func() { dnsRetryAfter = old }()
	// the file names a DNS server that never answers (10.9.0.2); 10.9.0.1 does
	conf := wgDNSServer(t, 7, "DNS = 10.9.0.2\n")
	e, apps := newTestEngine(t, map[string]any{
		"tunnels":     []map[string]string{{"name": "t", "conf": conf}},
		"default":     "tunnel:t",
		"dns_servers": []string{"10.9.0.1"},
	})
	if got := e.dnsServers("tunnel:t"); len(got) != 2 || got[0] != netip.MustParseAddr("10.9.0.2") {
		t.Fatalf("server list %v", got)
	}
	if got, err := resolve(apps, "x.test."); err != nil || got != "192.0.2.7" {
		t.Fatalf("with a dead tunnel DNS the fallback must answer: %q %v", got, err)
	}
	// the one that answered is asked first now
	if got := e.dnsServers("tunnel:t"); got[0] != netip.MustParseAddr("10.9.0.1") {
		t.Errorf("answering server not preferred: %v", got)
	}

	// ignore the tunnel's DNS: only the extra servers
	cfg, _ := json.Marshal(map[string]any{"tunnels": []map[string]string{{"name": "t", "conf": conf}}, "default": "tunnel:t",
		"dns_servers": []string{"10.9.0.1"}, "ignore_tunnel_dns": true})
	if err := e.SetRules(string(cfg)); err != nil {
		t.Fatal(err)
	}
	e.dnsGood = dnsGoods{}
	if got := e.dnsServers("tunnel:t"); len(got) != 1 || got[0] != netip.MustParseAddr("10.9.0.1") {
		t.Errorf("ignored tunnel DNS still listed: %v", got)
	}
	if got, err := resolve(apps, "z.test."); err != nil || got != "192.0.2.7" {
		t.Errorf("query with ignored tunnel DNS: %q %v", got, err)
	}
}

func TestDNSServersConfig(t *testing.T) {
	if _, err := parseConfig(`{"dns_servers":["1.1.1.1","nonsense"]}`); err == nil {
		t.Error("an invalid DNS server was accepted")
	}
	c, err := parseConfig(`{"dns_servers":["1.1.1.1","8.8.8.8","2606:4700:4700::1111"],"on_demand":true}`)
	if err != nil || len(c.DNSServers) != 3 || !c.OnDemand {
		t.Errorf("%+v %v", c, err)
	}
}
