package splitstack

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// With TOR_FAKE=1 this test binary plays the tor program: it reads the ports
// and the cookie file from the torrc it is given, serves a control port
// (cookie authentication, GETINFO status/bootstrap-phase, SIGNAL NEWNYM) and
// listens on the SOCKS port.
func TestMain(m *testing.M) {
	if os.Getenv("TOR_FAKE") == "1" {
		fakeTorMain()
		return
	}
	os.Exit(m.Run())
}

func fakeTorMain() {
	var rc string
	for i, a := range os.Args {
		if a == "-f" && i+1 < len(os.Args) {
			b, _ := os.ReadFile(os.Args[i+1])
			rc = string(b)
		}
	}
	var socks, ctl, cookieFile string
	for _, l := range strings.Split(rc, "\n") {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "SOCKSPort":
			socks = f[1]
		case "ControlPort":
			ctl = f[1]
		case "CookieAuthFile":
			cookieFile = f[1]
		}
	}
	cookie := []byte("0123456789abcdef0123456789abcdef")
	os.WriteFile(cookieFile, cookie, 0o600)
	sl, err := net.Listen("tcp", socks)
	if err != nil {
		os.Exit(2)
	}
	go func() {
		for {
			c, err := sl.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	cl, err := net.Listen("tcp", ctl)
	if err != nil {
		os.Exit(3)
	}
	start := time.Now()
	for {
		c, err := cl.Accept()
		if err != nil {
			os.Exit(0)
		}
		go func() {
			defer c.Close()
			r := bufio.NewReader(c)
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				l = strings.TrimSpace(l)
				switch {
				case strings.HasPrefix(l, "AUTHENTICATE"):
					if l != "AUTHENTICATE "+hex.EncodeToString(cookie) {
						fmt.Fprint(c, "515 bad\r\n")
						return
					}
					fmt.Fprint(c, "250 OK\r\n")
				case strings.HasPrefix(l, "GETINFO status/bootstrap-phase"):
					p := 100
					if time.Since(start) < 1500*time.Millisecond {
						p = 40
					}
					fmt.Fprintf(c, "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=%d TAG=x SUMMARY=\"y\"\r\n250 OK\r\n", p)
				case l == "SIGNAL NEWNYM":
					fmt.Fprint(c, "250 OK\r\n")
				default:
					fmt.Fprint(c, "510 unrecognized\r\n")
				}
			}
		}()
	}
}

func TestTorProc(t *testing.T) {
	t.Setenv("TOR_FAKE", "1")
	exe, _ := os.Executable()
	tt, err := newTorTunnel("client = builtin\nbridge = snowflake\n")
	if err != nil || !tt.conf.Builtin {
		t.Fatalf("conf: %+v %v", tt, err)
	}
	if err := tt.startBuiltin(exe, "/pt/lyrebird", t.TempDir(), t.Logf); err != nil {
		t.Fatal(err)
	}
	defer tt.close()
	rc, _ := os.ReadFile(tt.proc.dir + "/torrc")
	for _, want := range []string{"UseBridges 1", "ClientTransportPlugin obfs4,meek_lite,webtunnel,snowflake exec /pt/lyrebird", "Bridge snowflake ", "SOCKSPort 127.0.0.1:"} {
		if !strings.Contains(string(rc), want) {
			t.Errorf("torrc lacks %q:\n%s", want, rc)
		}
	}
	deadline := time.Now().Add(10 * time.Second)
	sawStarting := false
	for time.Now().Before(deadline) {
		if st := tt.status("t"); !st.Up && strings.Contains(st.Error, "Tor is starting") {
			sawStarting = true
		}
		if tt.proc.Bootstrap() == 100 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if tt.proc.Bootstrap() != 100 {
		t.Fatalf("bootstrap %d, err %q", tt.proc.Bootstrap(), tt.proc.Err())
	}
	if !sawStarting {
		t.Error("never saw the starting state")
	}
	time.Sleep(3500 * time.Millisecond) // reachable() caches for 3 s
	if !tt.reachable() {
		t.Error("not reachable at 100 %")
	}
	if err := tt.proc.NewIdentity(); err != nil {
		t.Errorf("newnym: %v", err)
	}
}

func TestTorConfBuiltin(t *testing.T) {
	if _, err := parseTorConf("client = nope"); err == nil {
		t.Error("accepted client = nope")
	}
	tt, _ := newTorTunnel("socks = 127.0.0.1:9050")
	if err := tt.startBuiltin("", "", "", t.Logf); err == nil {
		t.Error("builtin without a tor program")
	}
}
