package splitstack

import (
	"context"
	"encoding/json"
	"io"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const testOVPN = `client
dev tun
proto udp
remote vpn.example.org 1194
script-security 2
up /etc/openvpn/update-resolv-conf
<ca>
-----BEGIN CERTIFICATE-----
x
-----END CERTIFICATE-----
</ca>
`

func TestCheckOpenVPN(t *testing.T) {
	out, err := CheckOpenVPN(testOVPN)
	if err != nil {
		t.Fatal(err)
	}
	var sum struct {
		Remotes []string
		Removed []string
		Clean   string
		TLSWrap bool `json:"tls_wrap"`
	}
	json.Unmarshal([]byte(out), &sum)
	if len(sum.Remotes) != 1 || len(sum.Removed) != 2 || strings.Contains(sum.Clean, "\nup ") || sum.TLSWrap {
		t.Errorf("summary %s", out)
	}
	wrapped := strings.Replace(testOVPN, "<ca>", "<tls-crypt>\nk\n</tls-crypt>\n<ca>", 1)
	if out, err := CheckOpenVPN(wrapped); err != nil || !strings.Contains(out, `"tls_wrap":true`) {
		t.Errorf("tls-crypt not seen: %s %v", out, err)
	}
	if _, err := CheckOpenVPN("client\nremote a 1194\nca /etc/ca.crt\n"); err == nil || !strings.Contains(err.Error(), "inline") {
		t.Errorf("file reference: %v", err)
	}
	if _, err := CheckOpenVPN("server 10.8.0.0 255.255.255.0\n"); err == nil {
		t.Error("server config accepted")
	}
	if _, err := CheckOpenVPN("client\ndev tun\n"); err == nil {
		t.Error("config without remote accepted")
	}
}

// Without the openvpn program an OpenVPN tunnel is reported down and its
// apps are blocked (fail closed), the engine still starts.
func TestOpenVPNUnavailable(t *testing.T) {
	cfg, _ := json.Marshal(map[string]any{
		"tunnels": []map[string]string{{"name": "o", "type": "openvpn", "conf": testOVPN}},
		"default": "tunnel:o",
	})
	appDev, _, _ := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.111.0.2")}, nil, 1280)
	link, stop := TunLink(appDev, 1280)
	defer appDev.Close()
	defer stop()
	e, err := New(Options{Link: link}, string(cfg))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Stop()
	var st struct {
		Tunnels []tunnelStatus `json:"tunnels"`
	}
	json.Unmarshal([]byte(e.Status()), &st)
	if len(st.Tunnels) != 1 || st.Tunnels[0].Up || st.Tunnels[0].Type != "openvpn" || st.Tunnels[0].Error == "" {
		t.Errorf("status %+v", st.Tunnels)
	}
}

// End to end with the real openvpn (Android mode, built for this machine:
// ABIS=host android/build-openvpn.sh) against a real server:
//
//	SHUNT_TEST_OPENVPN=~/.cache/shunt-openvpn/host/openvpn \
//	SHUNT_TEST_OVPN_CONF=~/.config/shunt-testserver/ovpn-intern-linux-test.ovpn \
//	SHUNT_TEST_OVPN_URL=10.67.0.1:80 go test -run OpenVPNTunnel ./internal/splitstack
//
// The server's test page (testserver-intern) answers "tunnel=… client=…".
func TestOpenVPNTunnel(t *testing.T) {
	exe, confPath, target := os.Getenv("SHUNT_TEST_OPENVPN"), os.Getenv("SHUNT_TEST_OVPN_CONF"), os.Getenv("SHUNT_TEST_OVPN_URL")
	if exe == "" || confPath == "" || target == "" {
		t.Skip("SHUNT_TEST_OPENVPN, SHUNT_TEST_OVPN_CONF, SHUNT_TEST_OVPN_URL not set")
	}
	conf, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ := json.Marshal(map[string]any{
		"tunnels":  []map[string]string{{"name": "o", "type": "openvpn", "conf": string(conf)}},
		"default":  "tunnel:o",
		"openvpn":  exe,
		"work_dir": t.TempDir(),
	})
	appDev, apps, _ := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.111.0.2")}, nil, 1280)
	link, stop := TunLink(appDev, 1280)
	defer appDev.Close()
	defer stop()
	e, err := New(Options{Link: link, HealthEvery: time.Second, Log: func(s string) { t.Log(s) }}, string(cfg))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Stop()

	get := func() string {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		c, err := apps.DialContextTCPAddrPort(ctx, netip.MustParseAddrPort(target))
		if err != nil {
			return err.Error()
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		c.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
		b, _ := io.ReadAll(c)
		return string(b)
	}
	var body string
	for i := 0; i < 30 && !strings.Contains(body, "tunnel="); i++ {
		body = get()
		if !strings.Contains(body, "tunnel=") {
			time.Sleep(500 * time.Millisecond)
		}
	}
	if !strings.Contains(body, "tunnel=") {
		t.Fatalf("test page through the OpenVPN tunnel: %q", body)
	}
	t.Logf("test page: %s", body[strings.Index(body, "tunnel="):])

	// DNS of an app goes to the server's pushed DNS, through the tunnel
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	q, _ := m.Pack()
	uc, err := apps.DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(netip.MustParseAddr(DNSAddr), 53))
	if err != nil {
		t.Fatal(err)
	}
	uc.SetDeadline(time.Now().Add(5 * time.Second))
	uc.Write(q)
	buf := make([]byte, 1500)
	n, err := uc.Read(buf)
	uc.Close()
	r := new(dns.Msg)
	if err != nil || r.Unpack(buf[:n]) != nil || len(r.Answer) == 0 {
		t.Errorf("DNS through the OpenVPN tunnel: %v %v", err, r)
	}

	// status: type, up, health ok after a probe round, bytes counted
	var st struct {
		Tunnels []tunnelStatus `json:"tunnels"`
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		json.Unmarshal([]byte(e.Status()), &st)
		if s := st.Tunnels[0]; s.Up && s.Health.State == "ok" && s.TX > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if s := st.Tunnels[0]; s.Type != "openvpn" || !s.Up || s.Health.State != "ok" || s.TX == 0 {
		t.Errorf("status %+v", s)
	}

	// network change: openvpn reconnects and the tunnel works again
	e.NetworkChanged()
	time.Sleep(time.Second)
	body = ""
	for i := 0; i < 30 && !strings.Contains(body, "tunnel="); i++ {
		body = get()
		if !strings.Contains(body, "tunnel=") {
			time.Sleep(500 * time.Millisecond)
		}
	}
	if !strings.Contains(body, "tunnel=") {
		t.Errorf("after a network change: %q", body)
	}

	// openvpn crashes: the health loop starts it again
	ovpnRestartGap = time.Second
	defer func() { ovpnRestartGap = 30 * time.Second }()
	if p, err := os.FindProcess(e.tunnels["o"].ovpnTunnel().Pid()); err == nil {
		p.Kill()
	}
	body = ""
	for i := 0; i < 40 && !strings.Contains(body, "tunnel="); i++ {
		body = get()
		if !strings.Contains(body, "tunnel=") {
			time.Sleep(500 * time.Millisecond)
		}
	}
	if !strings.Contains(body, "tunnel=") {
		t.Errorf("after openvpn was killed: %q", body)
	}
}
