package splitstack

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/socks"
)

func TestParseTorConf(t *testing.T) {
	c, err := parseTorConf("")
	if err != nil || c.Socks != "127.0.0.1:9050" || c.DNS != "127.0.0.1:5400" {
		t.Errorf("defaults: %+v %v", c, err)
	}
	c, err = parseTorConf("# orbot\nsocks = 127.0.0.1:9150\ndns=127.0.0.1:5353\n")
	if err != nil || c.Socks != "127.0.0.1:9150" || c.DNS != "127.0.0.1:5353" {
		t.Errorf("custom: %+v %v", c, err)
	}
	for _, bad := range []string{"socks = 8.8.8.8:9050", "socks = localhost:9050", "proxy = 127.0.0.1:1", "socks"} {
		if _, err := parseTorConf(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

// A fake Tor client: SOCKS5 server that records what it was asked and echoes;
// a fake DNSPort that answers every datagram with "dns:" + the datagram.
func fakeTor(t *testing.T) (conf string, targets chan string) {
	targets = make(chan string, 4)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	srv := &socks.Server{Remote: true, Dial: func(_ context.Context, _, addr string) (net.Conn, error) {
		targets <- addr
		a, b := net.Pipe()
		go func() { defer b.Close(); _, _ = io.Copy(b, b) }()
		return a, nil
	}}
	go srv.Serve(l)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(append([]byte("dns:"), buf[:n]...), from)
		}
	}()
	return "socks = " + l.Addr().String() + "\ndns = " + pc.LocalAddr().String() + "\n", targets
}

func TestTorTunnelDial(t *testing.T) {
	conf, targets := fakeTor(t)
	tt, err := newTorTunnel(conf)
	if err != nil {
		t.Fatal(err)
	}
	if !tt.reachable() {
		t.Fatal("fake tor not reachable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := tt.dial(ctx, true, netip.MustParseAddrPort("203.0.113.5:443"))
	if err != nil {
		t.Fatal(err)
	}
	c.Write([]byte("hello"))
	buf := make([]byte, 5)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "hello" {
		t.Errorf("echo: %q %v", buf, err)
	}
	c.Close()
	if got := <-targets; got != "203.0.113.5:443" {
		t.Errorf("tor was asked for %q", got)
	}
	if st := tt.status("t"); !st.Up || st.RX == 0 || st.TX == 0 {
		t.Errorf("status: %+v", st)
	}
	// DNS goes to the DNSPort
	d, err := tt.dial(ctx, false, netip.AddrPortFrom(torDNS, 53))
	if err != nil {
		t.Fatal(err)
	}
	d.Write([]byte("q"))
	d.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _ := d.Read(buf)
	if string(buf[:n]) != "dns:q" {
		t.Errorf("dns: %q", buf[:n])
	}
	d.Close()
	// everything else over UDP is refused
	if _, err := tt.dial(ctx, false, netip.MustParseAddrPort("1.1.1.1:443")); err == nil || !strings.Contains(err.Error(), "TCP only") {
		t.Errorf("udp: %v", err)
	}
}

func TestTorTunnelDown(t *testing.T) {
	tt, _ := newTorTunnel("socks = 127.0.0.1:1")
	if tt.reachable() {
		t.Error("nothing listens on port 1")
	}
	if _, err := tt.dial(context.Background(), true, netip.MustParseAddrPort("203.0.113.5:443")); err == nil {
		t.Error("dial without tor succeeded")
	}
	if st := tt.status("t"); st.Up || st.Error == "" {
		t.Errorf("status: %+v", st)
	}
}

// The engine accepts a "tor" tunnel and routes the stack's calls to it.
func TestEngineTorTunnelType(t *testing.T) {
	var c config
	c.Tunnels = []tunnelConf{{Name: "tor", Type: "tor", Conf: "socks = 127.0.0.1:9050"}}
	wt := &wgTunnel{name: "tor", torType: true}
	wt.tor, _ = newTorTunnel(c.Tunnels[0].Conf)
	if !wt.up() || !wt.reachable() || wt.dnsAddr() != torDNS || wt.status().Type != typeTor {
		t.Errorf("wrapper: up %v reach %v dns %v st %+v", wt.up(), wt.reachable(), wt.dnsAddr(), wt.status())
	}
	if v4, v6 := wt.families(); !v4 || v6 {
		t.Error("families")
	}
}
