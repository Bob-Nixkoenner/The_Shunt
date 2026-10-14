package splitstack

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// A tunnel in use is probed (latency, state ok); when its server goes
// away the state turns stale/down.
func TestTunnelHealth(t *testing.T) {
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
	sdev.IpcSet(fmt.Sprintf("private_key=%x\nlisten_port=%d\npublic_key=%x\nallowed_ip=10.9.0.2/32\n", spriv[:], port, cpub[:]))
	sdev.Up()
	defer sdev.Close()
	u, _ := snet.ListenUDPAddrPort(netip.MustParseAddrPort("10.9.0.1:53"))
	go func() { // answers anything: the probe only needs a datagram back
		buf := make([]byte, 1500)
		for {
			n, a, err := u.ReadFrom(buf)
			if err != nil {
				return
			}
			u.WriteTo(buf[:n], a)
		}
	}()
	l, _ := snet.ListenTCPAddrPort(netip.MustParseAddrPort("10.9.0.1:7"))
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()

	b64 := func(k wgtypes.Key) string { return base64.StdEncoding.EncodeToString(k[:]) }
	spub := spriv.PublicKey()
	conf := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.9.0.2/32\nDNS = 10.9.0.1\n\n[Peer]\nPublicKey = %s\nEndpoint = 127.0.0.1:%d\nAllowedIPs = 0.0.0.0/0\n", b64(cpriv), b64(spub), port)
	cfg, _ := json.Marshal(map[string]any{"tunnels": []map[string]string{{"name": "t", "conf": conf}}, "default": "tunnel:t"})
	appDev, apps, _ := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.111.0.2")}, nil, 1280)
	link, stop := TunLink(appDev, 1280)
	defer appDev.Close()
	defer stop()
	e, err := New(Options{Link: link, HealthEvery: 50 * time.Millisecond}, string(cfg))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Stop()

	use := func() { // some traffic, so the tunnel counts as in use
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		if c, err := apps.DialContextTCPAddrPort(ctx, netip.MustParseAddrPort("10.9.0.1:7")); err == nil {
			c.Write([]byte("x"))
			c.Close()
		}
	}
	state := func() (string, int64) {
		var st struct {
			Tunnels []struct {
				Health struct {
					State     string `json:"state"`
					LatencyMs int64  `json:"latency_ms"`
					Loss      float64
				} `json:"health"`
			} `json:"tunnels"`
		}
		json.Unmarshal([]byte(e.Status()), &st)
		return st.Tunnels[0].Health.State, st.Tunnels[0].Health.LatencyMs
	}
	waitFor := func(want ...string) string {
		var s string
		for i := 0; i < 100; i++ {
			use()
			s, _ = state()
			for _, w := range want {
				if s == w {
					return s
				}
			}
			time.Sleep(50 * time.Millisecond)
		}
		return s
	}
	if s := waitFor("ok"); s != "ok" {
		t.Fatalf("working tunnel: state %q", s)
	}
	sdev.Close() // the server is gone
	if s := waitFor("stale", "down"); s != "stale" && s != "down" {
		t.Fatalf("dead tunnel: state %q", s)
	}
}
