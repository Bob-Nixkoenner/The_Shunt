package splitstack

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/probe"
	"github.com/miekg/dns"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestLeakTest(t *testing.T) {
	spriv, _ := wgtypes.GeneratePrivateKey()
	cpriv, _ := wgtypes.GeneratePrivateKey()
	stun, snet, _ := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.9.0.1")}, nil, 1420)
	sdev := device.NewDevice(stun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	pc, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	port := pc.LocalAddr().(*net.UDPAddr).Port
	pc.Close()
	cpub := cpriv.PublicKey()
	sdev.IpcSet(fmt.Sprintf("private_key=%x\nlisten_port=%d\npublic_key=%x\nallowed_ip=10.9.0.2/32\n", spriv[:], port, cpub[:]))
	sdev.Up()
	defer sdev.Close()
	// "the internet" behind the tunnel: our public IP and which resolver asked
	l, _ := snet.ListenTCPAddrPort(netip.MustParseAddrPort("10.9.0.1:80"))
	go http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "203.0.113.7") }))
	u, _ := snet.ListenUDPAddrPort(netip.MustParseAddrPort("10.9.0.1:53"))
	go dns.ActivateAndServe(nil, u, dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		r := new(dns.Msg)
		r.SetReply(q)
		if q.Question[0].Qtype == dns.TypeTXT {
			rr, _ := dns.NewRR(q.Question[0].Name + ` 60 IN TXT "198.51.100.53"`)
			r.Answer = append(r.Answer, rr)
		}
		if q.Question[0].Qtype == dns.TypeA && q.Question[0].Name == "lists.test." {
			rr, _ := dns.NewRR("lists.test. 60 IN A 10.9.0.1")
			r.Answer = append(r.Answer, rr)
		}
		w.WriteMsg(r)
	}))
	old := probe.IPURL
	probe.IPURL = "http://10.9.0.1/"
	defer func() { probe.IPURL = old }()

	b64 := func(k wgtypes.Key) string { return base64.StdEncoding.EncodeToString(k[:]) }
	spub := spriv.PublicKey()
	conf := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.9.0.2/32\nDNS = 10.9.0.1\n\n[Peer]\nPublicKey = %s\nEndpoint = 127.0.0.1:%d\nAllowedIPs = 0.0.0.0/0\n", b64(cpriv), b64(spub), port)
	cfg, _ := json.Marshal(map[string]any{"tunnels": []map[string]string{{"name": "t", "conf": conf}}, "default": "tunnel:t"})
	appDev, _, _ := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.111.0.2")}, nil, 1280)
	link, stop := TunLink(appDev, 1280)
	defer appDev.Close()
	defer stop()
	var d net.Dialer
	e, err := New(Options{Link: link, DialDirect: func(ctx context.Context, network, addr string) (net.Conn, error) {
		if network == "udp" && addr == "127.0.0.1:"+fmt.Sprint(port) {
			return d.DialContext(ctx, network, addr) // WireGuard's endpoint lookup is not needed (IP)
		}
		return nil, errors.New("no direct internet in this test")
	}}, string(cfg))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var res []probe.RouteResult
	if err := json.Unmarshal([]byte(e.LeakTest(ctx)), &res); err != nil {
		t.Fatal(err)
	}
	got := map[string]probe.RouteResult{}
	for _, r := range res {
		got[r.Route] = r
	}
	if r := got["tunnel:t"]; r.Result.IP != "203.0.113.7" || r.Result.Resolver != "198.51.100.53" || r.Verdict != "ok" {
		t.Errorf("tunnel: %+v", r)
	}
	if r := got["block"]; r.Verdict != "blocked" {
		t.Errorf("block: %+v", r)
	}
	if r := got["direct"]; r.Result.IP != "" {
		t.Errorf("direct reached the test internet: %+v", r)
	}

	// the service's own downloads take the default route, DNS included:
	// lists.test is only known to the tunnel's resolver, direct is dead
	cl := &http.Client{Transport: &http.Transport{DialContext: e.DialDefault}}
	resp, err := cl.Get("http://lists.test/")
	if err != nil {
		t.Fatalf("download through the default route: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "203.0.113.7" {
		t.Errorf("download: %q", body)
	}
}
