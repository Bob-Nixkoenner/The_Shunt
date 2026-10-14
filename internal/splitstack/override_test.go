package splitstack

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

// hostIP is an address of this machine that the engine can dial directly
// (loopback would not leave the apps' netstack).
func hostIP(t *testing.T) netip.Addr {
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil && p.Addr().Is4() && !p.Addr().IsLoopback() {
			return p.Addr()
		}
	}
	t.Skip("no non-loopback IPv4 address")
	return netip.Addr{}
}

func TestPanicAndPass(t *testing.T) {
	ip := hostIP(t)
	l, err := net.Listen("tcp4", net.JoinHostPort(ip.String(), "0"))
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
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	dst := netip.MustParseAddrPort(l.Addr().String())

	appDev, apps, _ := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.111.0.2")}, nil, 1280)
	link, stop := TunLink(appDev, 1280)
	defer appDev.Close()
	defer stop()
	cfg, _ := json.Marshal(map[string]any{"default": "direct"})
	e, err := New(Options{Link: link}, string(cfg))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Stop()

	open := func() (net.Conn, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		c, err := apps.DialContextTCPAddrPort(ctx, dst)
		if err != nil {
			return nil, err
		}
		c.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := c.Write([]byte("hi")); err != nil {
			return nil, err
		}
		buf := make([]byte, 2)
		if _, err := io.ReadFull(c, buf); err != nil {
			return nil, err
		}
		c.SetDeadline(time.Time{})
		return c, nil
	}
	cutWithin := func(c net.Conn) bool { // the engine closed it: read ends
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, err := c.Read(make([]byte, 1))
		var ne net.Error
		return err != nil && !(errors.As(err, &ne) && ne.Timeout())
	}

	// panic cuts a running connection and blocks new ones
	c, err := open()
	if err != nil {
		t.Fatalf("direct: %v", err)
	}
	e.SetPanic(true)
	if !cutWithin(c) {
		t.Error("panic did not cut the running connection")
	}
	if _, err := open(); err == nil {
		t.Error("new connection during panic")
	}
	var cnt struct {
		Blocked int64 `json:"blocked"`
	}
	json.Unmarshal([]byte(e.Status()), &cnt)
	if cnt.Blocked < 1 {
		t.Errorf("connection refused by panic not counted as blocked (blocked = %d)", cnt.Blocked)
	}
	e.SetPanic(false)

	// a pass opens a blocked default for a while, its end cuts what it opened
	cfg, _ = json.Marshal(map[string]any{"default": "block"})
	if err := e.SetRules(string(cfg)); err != nil {
		t.Fatal(err)
	}
	if _, err := open(); err == nil {
		t.Fatal("blocked default got through")
	}
	if until := e.Pass(5 * time.Minute); time.Until(until) < 4*time.Minute {
		t.Fatalf("pass end %v", until)
	}
	c, err = open()
	if err != nil {
		t.Fatalf("during pass: %v", err)
	}
	var st struct {
		Override struct {
			PassLeft int64 `json:"pass_left"`
		} `json:"override"`
	}
	json.Unmarshal([]byte(e.Status()), &st)
	if st.Override.PassLeft < 290 {
		t.Errorf("status pass_left = %d", st.Override.PassLeft)
	}
	e.Pass(0)
	if !cutWithin(c) {
		t.Error("end of the pass did not cut the connection it opened")
	}
	if _, err := open(); err == nil {
		t.Error("blocked again after the pass, but got through")
	}
}
