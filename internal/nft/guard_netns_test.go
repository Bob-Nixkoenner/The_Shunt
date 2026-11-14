//go:build linux

package nft

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/Bob-Nixkoenner/the_shunt/internal/engine"
	"github.com/Bob-Nixkoenner/the_shunt/internal/socks"
)

// TestGuardNetns loads the loopback guard into a real kernel, in a network
// namespace of a user namespace of its own (`unshare -Urn`, no root):
//
//   - M-04: another program holds a SOCKS exit address; the manager reports
//     it, and with the guard TCP to it never reaches that program.
//   - M-06: a running exit rejects sockets of a denied cgroup and of users
//     not in socks_users, and lets the allowed ones through.
//   - shuntd stopped: TCP to Tor proxy ports and UDP to DNS listener ports
//     never reach a program that took them.
//
// Skipped where user namespaces or nft are not available.
func TestGuardNetns(t *testing.T) {
	if os.Getenv("SHUNT_GUARD_NETNS") != "1" {
		if _, err := exec.LookPath("nft"); err != nil {
			t.Skip("no nft:", err)
		}
		if _, err := exec.LookPath("unshare"); err != nil {
			t.Skip("no unshare:", err)
		}
		if err := exec.Command("unshare", "-Urn", "true").Run(); err != nil {
			t.Skip("no user/network namespaces:", err)
		}
		cmd := exec.Command("unshare", "-Urn", os.Args[0], "-test.run", "^TestGuardNetns$", "-test.v")
		cmd.Env = append(os.Environ(), "SHUNT_GUARD_NETNS=1")
		out, err := cmd.CombinedOutput()
		t.Logf("in the namespace:\n%s", out)
		if err != nil {
			t.Fatal("namespace run failed:", err)
		}
		if strings.Contains(string(out), "--- SKIP") {
			t.Skip("skipped in the namespace")
		}
		return
	}

	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		t.Fatal(err)
	}
	if err := Apply(DeleteScript(TorGuardTable)); err != nil {
		t.Skip("nft does not work here:", err)
	}
	guard := func(g Guard) {
		t.Helper()
		s, err := RenderGuard(g)
		if err != nil {
			t.Fatal(err)
		}
		if err := Apply(s); err != nil {
			t.Fatalf("%v\n%s", err, s)
		}
	}

	t.Run("M-04 taken SOCKS exit", func(t *testing.T) {
		squat, hits := squatTCP(t, "127.0.0.1:0")
		addr := squat.Addr().String()
		if !reaches(addr) || waitHits(hits) != 1 {
			t.Fatal("without the guard the squatter must be reachable (test set-up)")
		}
		m := &socks.Manager{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
		defer m.Close()
		taken := m.Update(map[string]socks.Exit{"t": {Listen: addr, Dial: noDial}})
		if len(taken) != 1 || m.States()["t"] != socks.StateTaken {
			t.Fatalf("taken = %v, states %v", taken, m.States())
		}
		guard(Guard{Socks: taken})
		if reaches(addr) {
			t.Fatal("connection to a taken exit address went through")
		}
		if n := waitHits(hits); n != 0 {
			t.Fatalf("the squatter got %d connection(s) through the guard", n)
		}
		guard(Guard{})
		if !reaches(addr) {
			t.Fatal("an empty guard must lift the block")
		}
	})

	t.Run("M-06 who may use a running exit", func(t *testing.T) {
		m := &socks.Manager{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
		defer m.Close()
		free, _ := squatTCP(t, "127.0.0.1:0")
		addr := free.Addr().String()
		free.Close()
		if taken := m.Update(map[string]socks.Exit{"t": {Listen: addr, Dial: noDial}}); len(taken) != 0 {
			t.Fatalf("free address reported taken: %v", taken)
		}
		ap := netip.MustParseAddrPort(addr)

		guard(Guard{Exits: []ExitGuard{{Addr: ap, Users: true, UIDs: []uint32{0}}}}) // we are uid 0 here
		if !socksOK(addr) {
			t.Fatal("an allowed user was turned away")
		}
		guard(Guard{Exits: []ExitGuard{{Addr: ap, Users: true, UIDs: []uint32{4242}}}})
		if !refused(addr) {
			t.Fatal("a user not in socks_users got through")
		}
		guard(Guard{Exits: []ExitGuard{{Addr: ap, Users: true}}})
		if !refused(addr) {
			t.Fatal("socks_users with no known user must let nobody in")
		}
		if g, ok := ownCgroup(); ok {
			guard(Guard{Exits: []ExitGuard{{Addr: ap, Deny: []engine.Group{g}}}})
			if !refused(addr) {
				t.Fatalf("a program in a denied cgroup (%s) got through", g.Path)
			}
		} else {
			t.Log("own cgroup path not usable in nft here: cgroup deny not checked")
		}
		if g, ok := otherCgroup(); ok {
			guard(Guard{Exits: []ExitGuard{{Addr: ap, Deny: []engine.Group{g}}}})
			if !socksOK(addr) {
				t.Fatalf("a program outside the denied cgroup (%s) was turned away", g.Path)
			}
		}
		guard(Guard{})
	})

	t.Run("shuntd stopped", func(t *testing.T) {
		tor, torHits := squatTCP(t, "127.0.0.1:0")
		torPort := tor.Addr().(*net.TCPAddr).Port
		dns, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer dns.Close()
		dnsHits := make(chan struct{}, 8)
		go func() {
			buf := make([]byte, 512)
			for {
				if _, _, err := dns.ReadFrom(buf); err != nil {
					return
				}
				dnsHits <- struct{}{}
			}
		}()
		dnsPort := dns.LocalAddr().(*net.UDPAddr).Port
		guard(Guard{TorPorts: []int{torPort}, DNSPorts: []int{dnsPort}})
		if reaches(tor.Addr().String()) || waitHits(torHits) != 0 {
			t.Fatal("TCP reached a program on a Tor proxy port while shuntd is stopped")
		}
		c, err := net.Dial("udp", dns.LocalAddr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_, _ = c.Write([]byte("query"))
		_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		_, rerr := c.Read(make([]byte, 16))
		if !errors.Is(rerr, syscall.ECONNREFUSED) {
			t.Errorf("DNS port: want a fast refusal, got %v", rerr)
		}
		select {
		case <-dnsHits:
			t.Fatal("UDP reached a program on a DNS listener port while shuntd is stopped")
		case <-time.After(300 * time.Millisecond):
		}
		guard(Guard{})
	})
}

func noDial(context.Context, string, string) (net.Conn, error) { return nil, net.ErrClosed }

// squatTCP listens on addr and counts accepted connections.
func squatTCP(t *testing.T, addr string) (net.Listener, chan struct{}) {
	t.Helper()
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	hits := make(chan struct{}, 8)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
			hits <- struct{}{}
		}
	}()
	return l, hits
}

func waitHits(hits chan struct{}) int {
	n := 0
	deadline := time.After(300 * time.Millisecond)
	for {
		select {
		case <-hits:
			n++
		case <-deadline:
			return n
		}
	}
}

func reaches(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, 700*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// refused: the connection is turned away at once (tcp reset), not dropped.
func refused(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err == nil {
		c.Close()
		return false
	}
	return errors.Is(err, syscall.ECONNREFUSED)
}

// socksOK: the exit answers a SOCKS5 greeting (no-auth accepted).
func socksOK(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return false
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		return false
	}
	var r [2]byte
	_, err = io.ReadFull(c, r[:])
	return err == nil && r == [2]byte{5, 0}
}

// ownCgroup is the deepest ancestor of this process's cgroup that nft
// can name (checkIdent refuses some characters systemd uses in unit names).
func ownCgroup() (engine.Group, bool) {
	raw, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return engine.Group{}, false
	}
	var p string
	for _, l := range strings.Split(string(raw), "\n") {
		if c, ok := strings.CutPrefix(l, "0::"); ok {
			p = strings.Trim(c, "/")
		}
	}
	for p != "" && checkIdent(p) != nil {
		i := strings.LastIndex(p, "/")
		if i < 0 {
			p = ""
			break
		}
		p = p[:i]
	}
	if p == "" {
		return engine.Group{}, false
	}
	return engine.Group{Name: "self", Path: p}, true
}

// otherCgroup is a top-level cgroup this process is not in.
func otherCgroup() (engine.Group, bool) {
	own, _ := ownCgroup()
	ents, err := os.ReadDir("/sys/fs/cgroup")
	if err != nil {
		return engine.Group{}, false
	}
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() && checkIdent(n) == nil && own.Path != n && !strings.HasPrefix(own.Path, n+"/") {
			return engine.Group{Name: "other", Path: n}, true
		}
	}
	return engine.Group{}, false
}
