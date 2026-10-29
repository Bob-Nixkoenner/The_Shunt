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
	if err != nil || c.Socks != "127.0.0.1:9050" || c.DNS != "" {
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

// Without "dns" names are resolved through the SOCKS port (RESOLVE, 0xF0).
func TestTorResolveViaSocks(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				b := make([]byte, 64)
				io.ReadFull(c, b[:3]) // greeting
				c.Write([]byte{5, 2})
				io.ReadFull(c, b[:2+5+2]) // 1, len("shunt"), user, 1, 'x'
				c.Write([]byte{1, 0})
				n, _ := c.Read(b)
				if n < 5 || b[1] != 0xF0 {
					return
				}
				if string(b[5:5+int(b[4])]) == "nope.example" {
					c.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				c.Write([]byte{5, 0, 0, 1, 192, 0, 2, 7, 0, 0})
			}()
		}
	}()
	tt, _ := newTorTunnel("socks = " + l.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	d, err := tt.dial(ctx, false, netip.AddrPortFrom(torDNS, 53))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	query := func(name string, qtype byte) []byte {
		q := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
		for _, lab := range strings.Split(name, ".") {
			q = append(q, byte(len(lab)))
			q = append(q, lab...)
		}
		q = append(q, 0, 0, qtype, 0, 1)
		d.Write(q)
		d.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 512)
		n, err := d.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		return buf[:n]
	}
	r := query("www.example.org", 1)
	if r[0] != 0x12 || r[3]&0xF != 0 || r[7] != 1 || string(r[len(r)-4:]) != "\xc0\x00\x02\x07" {
		t.Errorf("A answer: %x", r)
	}
	if r := query("www.example.org", 28); r[3]&0xF != 0 || r[7] != 0 {
		t.Errorf("AAAA answer: %x", r)
	}
	if r := query("nope.example", 1); r[3]&0xF != 3 {
		t.Errorf("failure should be NXDOMAIN: %x", r)
	}
}
