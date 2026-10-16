//go:build !android

package splitstack

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

// Against a real Headscale (test/integration/tailscale-tsnet.sh sets it up):
//
//	SHUNT_TS_LOGIN   login server URL
//	SHUNT_TS_KEY     pre-auth key
//	SHUNT_TS_EXIT    exit node (optional; without it only the tailnet is reachable)
//	SHUNT_TS_TARGET  ip:port of a whoami server behind the exit node
//	SHUNT_TS_WANT    what the body must contain when it works
func TestTailscaleLive(t *testing.T) {
	login, key, target := os.Getenv("SHUNT_TS_LOGIN"), os.Getenv("SHUNT_TS_KEY"), os.Getenv("SHUNT_TS_TARGET")
	if login == "" || key == "" || target == "" {
		t.Skip("SHUNT_TS_* not set")
	}
	exit := os.Getenv("SHUNT_TS_EXIT")
	conf := fmt.Sprintf("login_server = %s\nauth_key = %s\nhostname = shunt-live\n", login, key)
	if exit != "" {
		conf += "exit_node = " + exit + "\n"
	}
	tt, err := startTailscale("live", conf, t.TempDir(), t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer tt.close()
	deadline := time.Now().Add(60 * time.Second)
	for {
		up, _, _, _, perr := tt.status()
		if up {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("not connected after 60 s (%s)", perr)
		}
		time.Sleep(500 * time.Millisecond)
	}
	ap := netip.MustParseAddrPort(target)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, err := tt.dial(ctx, "tcp", ap)
	if exit == "" {
		if err == nil {
			c.Close()
			t.Fatal("dial outside the tailnet worked without an exit node: that would leak")
		}
		t.Logf("blocked as it should: %v", err)
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "GET / HTTP/1.0\r\nHost: x\r\n\r\n")
	b, _ := io.ReadAll(c)
	t.Logf("answer: %q", b)
	if want := os.Getenv("SHUNT_TS_WANT"); !strings.Contains(string(b), want) {
		t.Fatalf("answer does not contain %q", want)
	}
}
