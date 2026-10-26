package sockets

import (
	"net"
	"net/netip"
	"runtime"
	"testing"
)

func TestNameOf(t *testing.T) {
	for cg, want := range map[string]string{
		"user.slice/user-1000.slice/user@1000.service/app.slice/app-cosmic-discord-7187.scope":                      "discord",
		"user.slice/user-1000.slice/user@1000.service/app.slice/app-discord-7187.scope":                             "discord",
		"user.slice/user-1000.slice/user@1000.service/app.slice/app-gnome-firefox-1234.scope":                       "firefox",
		"user.slice/user-1000.slice/user@1000.service/app.slice/app-flatpak-im.riot.Riot-2007796032.scope":          "flatpak:im.riot.Riot",
		`user.slice/user-1000.slice/user@1000.service/app.slice/app-flatpak-io.github.cosmic\x2dext\x2dapp-1.scope`: "flatpak:io.github.cosmic-ext-app",
		"user.slice/user-1000.slice/user@1000.service/app.slice/app-org.kde.konsole@0a1b2c.service":                 "konsole",
		"user.slice/user-1000.slice/user@1000.service/app.slice/snap.brave.brave-1f2e.scope":                        "snap:brave",
		"system.slice/ssh.service":                           "ssh",
		"system.slice/systemd-resolved.service":              "systemd-resolved",
		"system.slice/system-getty.slice/getty@tty1.service": "getty",
		"user.slice/user-1000.slice/session-3.scope":         "login session",
		"init.scope":              "systemd",
		"system.slice/ssh.socket": "ssh",
	} {
		if o, _ := nameOf(cg); o.Name != want {
			t.Errorf("%s: %q, want %q", cg, o.Name, want)
		}
	}
	for _, cg := range []string{"user.slice/user-1000.slice/session-2.scope", "system.slice/shuntd.service/apps/via/tunnel-home", "user.slice"} {
		if _, generic := nameOf(cg); !generic {
			t.Errorf("%s: not generic", cg)
		}
	}
	if o, _ := nameOf("system.slice/ssh.service"); !o.System {
		t.Error("ssh not a system service")
	}
}

func TestListeningAndOwner(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	uc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	tport := netip.MustParseAddrPort(ln.Addr().String())
	uport := netip.MustParseAddrPort(uc.LocalAddr().String())

	ss, err := ListListening()
	if err != nil {
		t.Fatal(err)
	}
	var tcp, udp *Socket
	for i, s := range ss {
		switch {
		case s.Proto == "tcp" && s.Local == tport:
			tcp = &ss[i]
		case s.Proto == "udp" && s.Local == uport:
			udp = &ss[i]
		}
	}
	if tcp == nil || udp == nil {
		t.Fatalf("own sockets not listed: tcp %v udp %v", tcp, udp)
	}
	if tcp.Inode == 0 || tcp.Cgroup == 0 {
		t.Errorf("tcp socket without inode/cgroup: %+v", *tcp)
	}

	// a connected client: found by its source address, owner = this test
	c, err := net.Dial("udp", uc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var r Resolver
	o, ok := r.Of("udp", netip.MustParseAddrPort(c.LocalAddr().String()))
	if !ok || len(o.Procs) == 0 {
		t.Fatalf("owner of own client not found: %+v %v", o, ok)
	}
}
