package splitstack

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestViaRewrite: remotes point to local relays that reach the real
// server through the dial function (here: plain network, with a check
// that every connection goes through it).
func TestViaRewrite(t *testing.T) {
	// UDP echo "server"
	us, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer us.Close()
	go func() {
		buf := make([]byte, 2000)
		for {
			n, a, err := us.ReadFromUDP(buf)
			if err != nil {
				return
			}
			us.WriteToUDP(append([]byte("udp:"), buf[:n]...), a)
		}
	}()
	// TCP echo "server"
	ts, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()
	go func() {
		for {
			c, err := ts.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 2000)
				n, _ := c.Read(buf)
				c.Write(append([]byte("tcp:"), buf[:n]...))
			}()
		}
	}()
	_, uport, _ := net.SplitHostPort(us.LocalAddr().String())
	_, tport, _ := net.SplitHostPort(ts.Addr().String())

	dialed := map[string]int{}
	var dmu sync.Mutex // the UDP and TCP relays dial from their own goroutines
	var d net.Dialer
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dmu.Lock()
		dialed[network+" "+addr]++
		dmu.Unlock()
		return d.DialContext(ctx, network, addr)
	}
	conf := "client\nproto udp\nport " + uport + "\nremote 127.0.0.1\nremote 127.0.0.1 " + tport + " tcp\n<ca>\nremote inside block\n</ca>\n"
	out, r, err := viaRewrite(conf, dial)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	var udpLocal, tcpLocal string
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) >= 4 && f[0] == "remote" && f[1] == "127.0.0.1" {
			switch f[3] {
			case "udp":
				udpLocal = net.JoinHostPort(f[1], f[2])
			case "tcp-client":
				tcpLocal = net.JoinHostPort(f[1], f[2])
			}
		}
	}
	if udpLocal == "" || tcpLocal == "" {
		t.Fatalf("remotes not rewritten:\n%s", out)
	}

	c, err := net.Dial("udp4", udpLocal)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	for i := 0; i < 2; i++ { // second packet reuses the upstream
		c.Write([]byte("ping"))
		buf := make([]byte, 100)
		n, err := c.Read(buf)
		if err != nil || string(buf[:n]) != "udp:ping" {
			t.Fatalf("udp relay: %q %v", buf[:n], err)
		}
	}
	dmu.Lock()
	udpDials := dialed["udp 127.0.0.1:"+uport]
	dmu.Unlock()
	if udpDials != 1 {
		t.Errorf("udp dials: %d", udpDials)
	}

	tc, err := net.Dial("tcp4", tcpLocal)
	if err != nil {
		t.Fatal(err)
	}
	defer tc.Close()
	tc.SetDeadline(time.Now().Add(3 * time.Second))
	tc.Write([]byte("ping"))
	buf := make([]byte, 100)
	n, err := tc.Read(buf)
	if err != nil || string(buf[:n]) != "tcp:ping" {
		t.Fatalf("tcp relay: %q %v", buf[:n], err)
	}
}
