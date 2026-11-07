package splitstack

import (
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/wgconf"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// pipeTUNs joins two netstack devices like a wire.
func pipeTUNs(a, b tun.Device) {
	pump := func(src, dst tun.Device) {
		for {
			bufs := [][]byte{make([]byte, 2048)}
			sizes := []int{0}
			n, err := src.Read(bufs, sizes, 0)
			if err != nil {
				return
			}
			if n > 0 {
				dst.Write([][]byte{bufs[0][:sizes[0]]}, 0)
			}
		}
	}
	go pump(a, b)
	go pump(b, a)
}

func inboundSetup(t *testing.T, from []string) (peer *netstack.Net, stop func()) {
	t.Helper()
	atun, anet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.9.0.1")}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	btun, bnet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.9.0.2")}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	pipeTUNs(atun, btun)
	e := &Engine{o: Options{Log: func(s string) { t.Log(s) }}}
	tn := &wgTunnel{name: "x", net: anet, conf: &wgconf.Config{Addresses: []netip.Prefix{netip.MustParsePrefix("10.9.0.1/24")}}}
	return bnet, e.startInbound(tn, tunnelConf{Name: "x", Inbound: []string{"tcp/15716", "udp/15716"}, InboundFrom: from})
}

func TestInboundTCPAndUDP(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:15716")
	if err != nil {
		t.Skip(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	u, err := net.ListenPacket("udp", "127.0.0.1:15716")
	if err != nil {
		t.Skip(err)
	}
	defer u.Close()
	go func() {
		b := make([]byte, 1500)
		for {
			n, a, err := u.ReadFrom(b)
			if err != nil {
				return
			}
			u.WriteTo(b[:n], a)
		}
	}()

	peer, stop := inboundSetup(t, []string{"10.9.0.2"})
	defer stop()

	c, err := peer.DialContextTCPAddrPort(t.Context(), netip.MustParseAddrPort("10.9.0.1:15716"))
	if err != nil {
		t.Fatal(err)
	}
	c.Write([]byte("hallo"))
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 5)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "hallo" {
		t.Fatalf("tcp echo: %q %v", buf, err)
	}
	c.Close()

	uc, err := peer.DialUDPAddrPort(netip.AddrPort{}, netip.MustParseAddrPort("10.9.0.1:15716"))
	if err != nil {
		t.Fatal(err)
	}
	uc.Write([]byte("ping"))
	uc.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := uc.Read(buf)
	if err != nil || string(buf[:n]) != "ping" {
		t.Fatalf("udp echo: %q %v", buf[:n], err)
	}

	// a port that is not allowed is refused
	if c, err := peer.DialContextTCPAddrPort(t.Context(), netip.MustParseAddrPort("10.9.0.1:22")); err == nil {
		c.Close()
		t.Fatal("port 22 should be refused")
	}
}

func TestInboundOtherSourceRefused(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:15716")
	if err != nil {
		t.Skip(err)
	}
	defer l.Close()
	peer, stop := inboundSetup(t, []string{"10.9.0.99"})
	defer stop()
	c, err := peer.DialContextTCPAddrPort(t.Context(), netip.MustParseAddrPort("10.9.0.1:15716"))
	if err != nil {
		return // refused at connect: fine
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	c.Write([]byte("x"))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("data came back from a source that is not allowed")
	}
}

func TestParseInbound(t *testing.T) {
	if _, err := parseInboundPorts([]string{"tcp/1716", "UDP/1716"}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"1716", "icmp/1", "tcp/0", "tcp/70000", "tcp/x"} {
		if _, err := parseInboundPorts([]string{bad}); err == nil {
			t.Errorf("%q should fail", bad)
		}
	}
	if _, err := parseInboundFrom([]string{"nope"}); err == nil {
		t.Error("bad address accepted")
	}
}
