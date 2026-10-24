package splitstack

import (
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// testServer is a WireGuard server in a netstack (10.9.0.1) with an HTTP
// server that answers its name; bind nil = UDP on 127.0.0.1:port.
func testServer(t *testing.T, name string, port int, bind conn.Bind, endpoint string) (conf string, tnet *netstack.Net) {
	t.Helper()
	spriv, _ := wgtypes.GeneratePrivateKey()
	cpriv, _ := wgtypes.GeneratePrivateKey()
	cpub := cpriv.PublicKey()
	tdev, tnet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.9.0.1")}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	if bind == nil {
		bind = conn.NewDefaultBind()
	}
	dev := device.NewDevice(tdev, bind, device.NewLogger(device.LogLevelError, name+": "))
	if err := dev.IpcSet(fmt.Sprintf("private_key=%x\nlisten_port=%d\npublic_key=%x\nallowed_ip=10.9.0.2/32\n", spriv[:], port, cpub[:])); err != nil {
		t.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dev.Close)
	l, err := tnet.ListenTCPAddrPort(netip.MustParseAddrPort("10.9.0.1:80"))
	if err != nil {
		t.Fatal(err)
	}
	go http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "tunnel="+name) }))
	b64 := func(k wgtypes.Key) string { return base64.StdEncoding.EncodeToString(k[:]) }
	return fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.9.0.2/32\n\n[Peer]\nPublicKey = %s\nEndpoint = %s\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n",
		b64(cpriv), b64(spriv.PublicKey()), endpoint), tnet
}

func get(t *testing.T, n *netstack.Net) string {
	t.Helper()
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DialContext: n.DialContext}}
	r, err := c.Get("http://10.9.0.1/")
	if err != nil {
		return err.Error()
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return string(b)
}

// The inner server listens only inside the outer one: an answer from it
// proves the inner tunnel's packets went through the outer tunnel.
func TestWireGuardVia(t *testing.T) {
	l, _ := net.ListenPacket("udp", "127.0.0.1:0")
	port := l.LocalAddr().(*net.UDPAddr).Port
	l.Close()
	outerConf, outerSrv := testServer(t, "outer", port, nil, fmt.Sprintf("127.0.0.1:%d", port))
	innerBind := &tunnelBind{carrier: outerSrv, v4: netip.MustParseAddr("10.9.0.1")}
	innerConf, _ := testServer(t, "inner", 51903, innerBind, "10.9.0.1:51903")

	outer, err := newWGTunnel("outer", outerConf, nil, conn.NewDefaultBind(), nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	defer outer.dev.Close()
	if got := get(t, outer.net); got != "tunnel=outer" {
		t.Fatalf("outer: %s", got)
	}
	e := &Engine{tunnels: map[string]*wgTunnel{"outer": outer}}
	inner, err := e.newWGVia(tunnelConf{Name: "inner", Conf: innerConf, Via: "outer"}, 1280)
	if err != nil {
		t.Fatal(err)
	}
	defer inner.dev.Close()
	if got := get(t, inner.net); got != "tunnel=inner" {
		ic, _ := inner.dev.IpcGet()
		oc, _ := outer.dev.IpcGet()
		t.Fatalf("inner through outer: %s\ninner client: %s\nouter client: %s", got, ic, oc)
	}
	if st := inner.status(); st.Via != "outer" {
		t.Errorf("status via %q", st.Via)
	}
}
