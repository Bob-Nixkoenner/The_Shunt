package splitstack

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// wgDNSLog is a WireGuard peer whose 10.9.0.1:53 answers every A query
// with 192.0.2.<id> and records the names it was asked.
func wgDNSLog(t *testing.T, id byte) (conf string, asked func() []string) {
	t.Helper()
	spriv, _ := wgtypes.GeneratePrivateKey()
	cpriv, _ := wgtypes.GeneratePrivateKey()
	stun, snet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.9.0.1")}, nil, 1420)
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
	var mu sync.Mutex
	var names []string
	u, _ := snet.ListenUDPAddrPort(netip.MustParseAddrPort("10.9.0.1:53"))
	go dns.ActivateAndServe(nil, u, dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		if n := strings.TrimSuffix(q.Question[0].Name, "."); n != "" { // "": the health probe
			mu.Lock()
			names = append(names, n)
			mu.Unlock()
		}
		r := new(dns.Msg)
		r.SetReply(q)
		r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, id)}}
		w.WriteMsg(r)
	}))
	b64 := func(k wgtypes.Key) string { return base64.StdEncoding.EncodeToString(k[:]) }
	spub := spriv.PublicKey()
	conf = fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.9.0.3/32\nDNS = 10.9.0.1\n[Peer]\nPublicKey = %s\nEndpoint = 127.0.0.1:%d\nAllowedIPs = 0.0.0.0/0\n",
		b64(cpriv), b64(spub), port)
	return conf, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), names...)
	}
}

// fakeTorResolve is a Tor SOCKS port that resolves every name (RESOLVE) to
// 192.0.2.7 and records the names.
func fakeTorResolve(t *testing.T) (socksAddr string, asked func() []string) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	var mu sync.Mutex
	var names []string
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				b := make([]byte, 300)
				if _, err := io.ReadFull(c, b[:3]); err != nil { // greeting, user/pass
					return
				}
				c.Write([]byte{5, 2})
				if _, err := io.ReadFull(c, b[:2]); err != nil {
					return
				}
				if _, err := io.ReadFull(c, b[:int(b[1])+2]); err != nil { // user, 1, 'x'
					return
				}
				c.Write([]byte{1, 0})
				n, _ := c.Read(b)
				if n < 5 || b[1] != 0xF0 {
					return
				}
				mu.Lock()
				names = append(names, string(b[5:5+int(b[4])]))
				mu.Unlock()
				c.Write([]byte{5, 0, 0, 1, 192, 0, 2, 7, 0, 0})
			}()
		}
	}()
	return l.Addr().String(), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), names...)
	}
}

const svchost = `c:\windows\system32\svchost.exe`

// Windows: the DNS client service (svchost.exe) asks for every program. A
// query goes the route of the program that asked (Options.DNSAskers) when
// that is a tunnel or block; the default route never sees those names.
func TestDNSAskersRoute(t *testing.T) {
	old := routeDNSWait
	routeDNSWait = 400 * time.Millisecond
	defer func() { routeDNSWait = old }()

	home, homeAsked := wgDNSLog(t, 1)
	work, workAsked := wgDNSLog(t, 2)
	dead := regexp.MustCompile(`(?m)^Endpoint = .*$`).ReplaceAllString(home, "Endpoint = 127.0.0.1:9") // nobody answers
	torAddr, torAsked := fakeTorResolve(t)

	askers := map[string][]string{
		"w.test":     {`c:\lab\labwork.exe`},
		"t.test":     {`c:\lab\labtor.exe`},
		"td.test":    {`c:\lab\labtordown.exe`},
		"b.test":     {`c:\lab\labblock.exe`},
		"d.test":     {`c:\lab\labdead.exe`},
		"dir.test":   {`c:\lab\labdir.exe`},
		"self.test":  {svchost},
		"mixed.test": {`c:\lab\labdir.exe`, svchost, `c:\lab\labtor.exe`},
		"pin.test":   {Pinned("tunnel:work", `c:\lab\labfree.exe`)},
		"x.dom.test": {`c:\lab\labdom.exe`},
		"y.dir.test": {`c:\lab\labdom.exe`},
	}
	b, _ := json.Marshal(map[string]any{
		"tunnels": []map[string]string{
			{"name": "home", "conf": home},
			{"name": "work", "conf": work},
			{"name": "dead", "conf": dead},
			{"name": "tor", "type": "tor", "conf": "socks = " + torAddr},
			{"name": "tordown", "type": "tor", "conf": "socks = 127.0.0.1:1"},
		},
		"default": "tunnel:home",
		"apps": map[string]string{"labwork.exe": "tunnel:work", "labdead.exe": "tunnel:dead", "labtor.exe": "tunnel:tor",
			"labtordown.exe": "tunnel:tordown", "labblock.exe": "block", "labdir.exe": "direct"},
		"rules": []map[string]any{{"name": "dom", "apps": []string{"labdom.exe"}, "domains": []string{"dom.test"}, "route": "tunnel:work"},
			{"name": "dir", "apps": []string{"labdom.exe"}, "domains": []string{"dir.test"}, "route": "direct"}},
	})
	appDev, apps, _ := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.111.0.2")}, nil, 1280)
	link, stop := TunLink(appDev, 1280)
	t.Cleanup(func() { appDev.Close(); stop() })
	// the direct route's DNS: a local server answering 192.0.2.9
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var directMu sync.Mutex
	var directAsked []string
	go dns.ActivateAndServe(nil, pc, dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		directMu.Lock()
		directAsked = append(directAsked, strings.TrimSuffix(q.Question[0].Name, "."))
		directMu.Unlock()
		r := new(dns.Msg)
		r.SetReply(q)
		r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 9)}}
		w.WriteMsg(r)
	}))
	t.Cleanup(func() { pc.Close() })
	var calls sync.Map
	e, err := New(Options{Link: link, HealthEvery: time.Hour,
		DialDirect: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if network != "udp" || !strings.HasSuffix(addr, ":53") {
				return nil, fmt.Errorf("unexpected direct %s %s", network, addr)
			}
			var d net.Dialer
			return d.DialContext(ctx, "udp", pc.LocalAddr().String())
		},
		Owner: func(int, netip.AddrPort, netip.AddrPort) string { return svchost },
		DNSAskers: func(app, name string, arrived time.Time) []string {
			if app != svchost || arrived.IsZero() {
				t.Errorf("asked for %q by %q at %v", name, app, arrived)
			}
			calls.Store(name, true)
			return askers[strings.TrimSuffix(name, ".")]
		}}, string(b))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Stop)

	for _, c := range []struct{ name, want string }{
		{"w.test", "192.0.2.2"},     // the asker's tunnel
		{"t.test", "192.0.2.7"},     // through Tor
		{"td.test", "rcode 2"},      // Tor down: SERVFAIL, not the default route
		{"b.test", "rcode 5"},       // blocked: REFUSED
		{"d.test", "rcode 2"},       // tunnel without a handshake: no answer, SERVFAIL
		{"dir.test", "192.0.2.1"},   // direct programs keep the default route (no names in the clear)
		{"self.test", "192.0.2.1"},  // the service's own lookups
		{"none.test", "192.0.2.1"},  // nobody known
		{"mixed.test", "192.0.2.7"}, // one asker on Tor: Tor
		{"pin.test", "192.0.2.2"},   // started in a route (run --via)
		{"x.dom.test", "192.0.2.2"}, // the asker's domain rule
		{"y.dir.test", "192.0.2.9"}, // a domain rule says direct: the user named the domain
	} {
		got, err := resolve(apps, c.name+".")
		if err != nil || got != c.want {
			t.Errorf("%s: %q %v, want %q", c.name, got, err, c.want)
		}
	}
	if _, ok := calls.Load("w.test."); !ok {
		t.Error("DNSAskers not called")
	}
	want := map[string]bool{"dir.test": true, "self.test": true, "none.test": true}
	for _, n := range homeAsked() {
		if !want[n] {
			t.Errorf("default route was asked for %q", n)
		}
		delete(want, n)
	}
	if len(want) > 0 {
		t.Errorf("default route not asked for %v", want)
	}
	if got := strings.Join(workAsked(), " "); got != "w.test pin.test x.dom.test" {
		t.Errorf("work tunnel asked for %q", got)
	}
	if got := strings.Join(torAsked(), " "); got != "t.test mixed.test" {
		t.Errorf("Tor asked for %q", got)
	}
	directMu.Lock()
	if got := strings.Join(directAsked, " "); got != "y.dir.test" {
		t.Errorf("direct route asked for %q", got)
	}
	directMu.Unlock()
	// the domain rule learned the address: the asker's connection takes the rule's route
	if r, _ := e.ruleRoute(`c:\lab\labdom.exe`, 6, netip.MustParseAddrPort("192.0.2.2:443")); r != "tunnel:work" {
		t.Errorf("domain rule address not learned: route %q", r)
	}
}

// Without DNSAskers (Android: every app asks itself) nothing changes.
func TestDNSAskersOff(t *testing.T) {
	home, homeAsked := wgDNSLog(t, 1)
	e, apps := newTestEngine(t, map[string]any{
		"tunnels": []map[string]string{{"name": "home", "conf": home}},
		"default": "tunnel:home",
	})
	if r, _, ok := e.askedRoute(&flow{app: svchost, route: "tunnel:home"}, "x.test.", time.Now()); ok {
		t.Errorf("route %q without DNSAskers", r)
	}
	if got, err := resolve(apps, "x.test."); err != nil || got != "192.0.2.1" || len(homeAsked()) != 1 {
		t.Errorf("%q %v %v", got, err, homeAsked())
	}
}
