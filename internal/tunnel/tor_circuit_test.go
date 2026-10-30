//go:build linux || windows

package tunnel

import (
	"bufio"
	"net"
	"strings"
	"testing"
)

// fakeControl answers like tor's control port.
func fakeControl(t *testing.T) func(...string) ([]string, error) {
	t.Helper()
	replies := map[string]string{
		"GETINFO circuit-status": "250+circuit-status=\r\n" +
			"1 BUILT $AAAA~guard,$BBBB~mid,$CCCC~exit1 BUILD_FLAGS=NEED_CAPACITY PURPOSE=GENERAL TIME_CREATED=2026-10-30T10:00:00.000000\r\n" +
			"2 BUILT $AAAA~guard,$BBBB~mid,$DDDD~exit2 PURPOSE=GENERAL TIME_CREATED=2026-10-30T10:05:00.000000\r\n" +
			"3 BUILT $AAAA~guard,$EEEE~hs PURPOSE=HS_CLIENT_REND TIME_CREATED=2026-10-30T10:09:00.000000\r\n" +
			".\r\n250 OK\r\n",
		"GETINFO stream-status":             "250+stream-status=\r\n7 SUCCEEDED 1 example.org:443\r\n8 NEW 0 x.org:80\r\n.\r\n250 OK\r\n",
		"GETINFO ns/id/CCCC":                "250+ns/id/CCCC=\r\nr exit1 abc def 2026-10-30 10:00:00 203.0.113.9 9001 0\r\ns Exit Fast\r\n.\r\n250 OK\r\n",
		"GETINFO ip-to-country/203.0.113.9": "250-ip-to-country/203.0.113.9=de\r\n250 OK\r\n",
	}
	return func(cmds ...string) ([]string, error) {
		srv, cli := net.Pipe()
		go func() {
			defer srv.Close()
			rd := bufio.NewReader(srv)
			for {
				l, err := rd.ReadString('\n')
				if err != nil {
					return
				}
				l = strings.TrimSpace(l)
				if strings.HasPrefix(l, "AUTHENTICATE") {
					_, _ = srv.Write([]byte("250 OK\r\n"))
					continue
				}
				r, ok := replies[l]
				if !ok {
					r = "552 Unrecognized key\r\n"
				}
				_, _ = srv.Write([]byte(r))
			}
		}()
		defer cli.Close()
		return controlExchange(cli, []byte{1, 2}, cmds)
	}
}

func TestQueryCircuit(t *testing.T) {
	c, err := queryCircuit(fakeControl(t), true)
	if err != nil || c == nil {
		t.Fatalf("%v %v", c, err)
	}
	// circuit 1 carries the stream, although 2 is newer
	if c.Hops != 3 || c.Relay != "exit1" || c.IP != "203.0.113.9" || c.Country != "de" || !c.Bridge {
		t.Fatalf("%+v", c)
	}
}

func TestPickCircuitFallbackNewest(t *testing.T) {
	p := pickCircuit([]string{
		"1 BUILT $A~a,$B~b PURPOSE=GENERAL TIME_CREATED=2026-10-30T10:00:00",
		"2 BUILT $A~a,$C~c,$D~d PURPOSE=GENERAL TIME_CREATED=2026-10-30T11:00:00",
		"3 EXTENDED $A~a PURPOSE=GENERAL TIME_CREATED=2026-10-30T12:00:00",
	})
	if len(p) != 3 {
		t.Fatalf("%v", p)
	}
	if pickCircuit(nil) != nil {
		t.Fatal("want nil")
	}
}

func TestControlError(t *testing.T) {
	_, err := fakeControl(t)("GETINFO nope")
	if err == nil {
		t.Fatal("want error")
	}
}
