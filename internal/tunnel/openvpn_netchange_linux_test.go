//go:build linux

package tunnel

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestDecideNetAction(t *testing.T) {
	a := netip.MustParseAddr
	oldIP, newIP := a("10.77.0.105"), a("10.77.0.191")
	tcp := []ovpnSock{{TCP: true, Local: oldIP}}
	udpUnbound := []ovpnSock{{Local: a("0.0.0.0")}, {Local: a("::")}}
	for _, c := range []struct {
		name    string
		socks   []ovpnSock
		host    []netip.Addr
		changed bool
		want    netAction
	}{
		{"tcp, source address gone", tcp, []netip.Addr{a("127.0.0.1"), newIP}, true, netRestart},
		{"tcp, same address after reconnect", tcp, []netip.Addr{a("127.0.0.1"), oldIP}, false, netNothing},
		{"tcp, address kept, another one added", tcp, []netip.Addr{oldIP, a("fd00::5")}, true, netRearm},
		{"udp unbound, new address: socket follows", udpUnbound, []netip.Addr{newIP}, true, netRearm},
		{"udp unbound, nothing changed", udpUnbound, []netip.Addr{newIP}, false, netNothing},
		{"udp bound to the gone address", []ovpnSock{{Local: oldIP}}, []netip.Addr{newIP}, true, netRestart},
		{"tcp over IPv6, address gone", []ovpnSock{{TCP: true, Local: a("2001:db8::1")}}, []netip.Addr{a("2001:db8::2")}, true, netRestart},
		{"no sockets (reconnecting)", nil, []netip.Addr{newIP}, false, netNothing},
	} {
		if got := decideNetAction(c.socks, c.host, c.changed); got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
}

func TestParseProcAddr(t *testing.T) {
	for h, want := range map[string]string{
		"6900A8C0":                         "192.168.0.105",
		"0100007F":                         "127.0.0.1",
		"00000000":                         "0.0.0.0",
		"B80D0120000000000000000001000000": "2001:db8::1",
		"0000000000000000FFFF00006900A8C0": "192.168.0.105", // v4-mapped
	} {
		got, ok := parseProcAddr(h)
		if !ok || got.String() != want {
			t.Errorf("%s: got %v %v, want %s", h, got, ok, want)
		}
	}
	if _, ok := parseProcAddr("zz"); ok {
		t.Error("bad hex accepted")
	}
}

// procSockets finds the process's own sockets in a fake /proc: its
// established TCP connection and unbound UDP socket, not other processes'
// sockets and not a listening one.
func TestProcSockets(t *testing.T) {
	root := t.TempDir()
	old := procRoot
	procRoot = root
	t.Cleanup(func() { procRoot = old })
	base := filepath.Join(root, "42")
	for _, d := range []string{"fd", "net"} {
		if err := os.MkdirAll(filepath.Join(base, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for fd, target := range map[string]string{"3": "socket:[1001]", "4": "socket:[1002]", "5": "socket:[1003]", "6": "/dev/net/tun"} {
		if err := os.Symlink(target, filepath.Join(base, "fd", fd)); err != nil {
			t.Fatal(err)
		}
	}
	hdr := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	files := map[string]string{
		"tcp": hdr +
			"   0: 6900A8C0:92EC 82DEA8C0:01BB 01 00006009:00000000 01:00000014 00000000     0        0 1001 1 0 20 4 30 10 -1\n" +
			"   1: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1003 1 0 100 0 0 10 0\n" +
			"   2: 0A00A8C0:1234 82DEA8C0:01BB 01 00000000:00000000 00:00000000 00000000     0        0 9999 1 0 20 4 30 10 -1\n",
		"tcp6": hdr,
		"udp":  hdr + "   7: 00000000:04AA 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 1002 2 0 0\n",
	}
	for n, c := range files {
		if err := os.WriteFile(filepath.Join(base, "net", n), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got := procSockets(42)
	want := []ovpnSock{{TCP: true, Local: netip.MustParseAddr("192.168.0.105")}, {Local: netip.MustParseAddr("0.0.0.0")}}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}
