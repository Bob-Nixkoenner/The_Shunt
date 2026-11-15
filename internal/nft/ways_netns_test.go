//go:build linux

package nft

import (
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"

	"github.com/vishvananda/netlink"

	"github.com/Bob-Nixkoenner/the_shunt/internal/engine"
)

// TestWaysNetns loads the counting table into a real kernel (network
// namespace of a user namespace of its own, no root) and sends UDP out of
// a dummy "uplink" and a dummy "tunnel": LAN and internet destinations
// count, the tunnel, the bypass mark and tunnel endpoints do not, and a
// second load keeps the counters. Skipped where that is not possible.
func TestWaysNetns(t *testing.T) {
	if os.Getenv("SHUNT_WAYS_NETNS") != "1" {
		if _, err := exec.LookPath("nft"); err != nil {
			t.Skip("no nft:", err)
		}
		if err := exec.Command("unshare", "-Urn", "true").Run(); err != nil {
			t.Skip("no user/network namespaces:", err)
		}
		cmd := exec.Command("unshare", "-Urn", os.Args[0], "-test.run", "^TestWaysNetns$", "-test.v")
		cmd.Env = append(os.Environ(), "SHUNT_WAYS_NETNS=1")
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

	link := func(name, addr string) netlink.Link {
		t.Helper()
		if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}); err != nil {
			t.Skip("cannot add a dummy link:", err)
		}
		l, err := netlink.LinkByName(name)
		if err != nil {
			t.Fatal(err)
		}
		a, _ := netlink.ParseAddr(addr)
		if err := netlink.AddrAdd(l, a); err != nil {
			t.Fatal(err)
		}
		if err := netlink.LinkSetUp(l); err != nil {
			t.Fatal(err)
		}
		return l
	}
	lo, _ := netlink.LinkByName("lo")
	_ = netlink.LinkSetUp(lo)
	up := link("up0", "192.168.77.1/24")
	tun := link("sh-t", "10.66.66.2/32")
	_, def, _ := net.ParseCIDR("0.0.0.0/0")
	if err := netlink.RouteAdd(&netlink.Route{LinkIndex: up.Attrs().Index, Dst: def, Gw: net.ParseIP("192.168.77.254")}); err != nil {
		t.Fatal(err)
	}
	_, tnet, _ := net.ParseCIDR("198.18.0.0/16")
	if err := netlink.RouteAdd(&netlink.Route{LinkIndex: tun.Attrs().Index, Dst: tnet}); err != nil {
		t.Fatal(err)
	}

	load := func() {
		t.Helper()
		s, err := RenderWays(Ways{TunnelIfaces: []string{"sh-t"}, Endpoints: []netip.Addr{netip.MustParseAddr("203.0.113.9")}})
		if err != nil {
			t.Fatal(err)
		}
		if err := Apply(s); err != nil {
			t.Fatalf("%v\n%s", err, s)
		}
	}
	load()

	send := func(dst string, n int, mark int) {
		t.Helper()
		d := &net.Dialer{}
		if mark != 0 {
			d.Control = func(_, _ string, c syscall.RawConn) error {
				var serr error
				_ = c.Control(func(fd uintptr) { serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, mark) })
				return serr
			}
		}
		c, err := d.Dial("udp4", dst)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if _, err := c.Write(make([]byte, n)); err != nil {
			t.Logf("write %s: %v", dst, err) // a dummy link drops, the count is what matters
		}
	}
	read := func() WayBytes {
		t.Helper()
		w, err := ReadWays()
		if err != nil {
			t.Fatal(err)
		}
		return w
	}

	send("192.168.77.5:9", 100, 0)                  // LAN
	send("198.51.100.1:9", 200, 0)                  // internet, direct
	send("198.18.0.1:9", 4000, 0)                   // through the tunnel
	send("203.0.113.9:51820", 4000, 0)              // tunnel endpoint
	send("8.8.8.8:9", 4000, int(engine.MarkBypass)) // a tunnel's own packet
	send("127.0.0.1:9", 4000, 0)                    // loopback
	w := read()
	if w.LANTX != 128 || w.DirectTX != 228 { // + 28 bytes IPv4/UDP header
		t.Fatalf("counted %+v, want lan_tx 128, direct_tx 228", w)
	}

	load() // a new plan: the totals stay
	send("192.168.77.5:9", 100, 0)
	if w := read(); w.LANTX != 256 || w.DirectTX != 228 {
		t.Fatalf("after reload %+v, want lan_tx 256, direct_tx 228", w)
	}
	if err := Apply(WaysOffScript()); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadWays(); err == nil {
		t.Fatal("table still there after WaysOffScript")
	}
}
