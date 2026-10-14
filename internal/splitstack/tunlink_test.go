package splitstack

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// TestTunLink drives the engine through TunLink, the way Windows does with
// wintun: the "apps" are a wireguard-go netstack whose TUN device is the
// engine's link. Traffic goes through a real WireGuard tunnel to an echo
// server; the owner callback plays the process lookup.
func TestTunLink(t *testing.T) {
	// WireGuard server with a TCP echo on 10.9.0.1:7
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
	conf := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.9.0.2/32\n\n[Peer]\nPublicKey = %s\nEndpoint = 127.0.0.1:%d\nAllowedIPs = 0.0.0.0/0\n", b64(cpriv), b64(spub), port)
	cfg, _ := json.Marshal(map[string]any{"tunnels": []map[string]string{{"name": "t", "conf": conf}}, "default": "block",
		"apps": map[string]string{`c:\apps\firefox.exe`: "tunnel:t"}})

	// the apps' side; its TUN device is the engine's link
	appDev, apps, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.111.0.2")}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	link, stop := TunLink(appDev, 1280)
	defer appDev.Close()
	defer stop()
	var app atomic.Value // the "process" that opens the next connection
	app.Store(`c:\apps\firefox.exe`)
	e, err := New(Options{Link: link, Owner: func(int, netip.AddrPort, netip.AddrPort) string { return app.Load().(string) }}, string(cfg))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Stop()

	echo := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := apps.DialContextTCPAddrPort(ctx, netip.MustParseAddrPort("10.9.0.1:7"))
		if err != nil {
			return err
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		c.Write([]byte("ping"))
		buf := make([]byte, 4)
		_, err = io.ReadFull(c, buf)
		return err
	}
	if err := echo(); err != nil {
		t.Fatalf("firefox through the tunnel: %v", err)
	}
	app.Store(`c:\apps\other.exe`)
	if err := echo(); err == nil {
		t.Fatal("other app (default block) got through")
	}
}
