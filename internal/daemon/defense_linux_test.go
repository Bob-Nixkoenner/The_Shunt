package daemon

import (
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	nflog "github.com/florianl/go-nflog/v2"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/Bob-Nixkoenner/the_shunt/internal/defense"
	"github.com/Bob-Nixkoenner/the_shunt/internal/engine"
	"github.com/Bob-Nixkoenner/the_shunt/internal/sockets"
)

// The DNS check asks a public resolver only through a tunnel that is the
// default route and carries UDP. Every other default route means: not asked
// (it would travel over the local network).
func TestTunnelMark(t *testing.T) {
	route := func(k config.RouteKind, mark uint32, iface string, tor bool) *engine.Route {
		return &engine.Route{Route: config.Route{Kind: k}, Mark: mark, Iface: iface, Tor: tor}
	}
	tun := engine.MarkBase | 1
	for _, c := range []struct {
		name string
		r    *engine.Route
		ok   bool
	}{
		{"tunnel", route(config.RouteTunnel, tun, "wg0", false), true},
		{"no plan", nil, false},
		{"direct", route(config.RouteDirect, engine.MarkDirect, "", false), false},
		{"block", route(config.RouteBlock, engine.MarkBlock, "", false), false},
		{"link", route(config.RouteLink, engine.MarkBase|engine.LinkSlot, "wlan0", false), false},
		{"tor", route(config.RouteTunnel, tun, "", true), false},
		{"tunnel without interface", route(config.RouteTunnel, tun, "", false), false},
	} {
		mark, ok := tunnelMark(c.r)
		if ok != c.ok || ok && mark != tun {
			t.Errorf("%s: mark %#x ok=%v", c.name, mark, ok)
		}
	}
	d := &Daemon{}
	if _, ok := d.defenseTunnelMark(); ok {
		t.Error("no plan yet: nothing to ask through")
	}
	d.plan = &engine.Plan{DefaultRoute: route(config.RouteTunnel, tun, "wg0", false)}
	if mark, ok := d.defenseTunnelMark(); !ok || mark != tun {
		t.Errorf("tunnel default route: %#x %v", mark, ok)
	}
}

// Lab R07 (2026-11-12): a socket in a cgroup that several programs share had
// no name, so first contact neither learned nor reported it. Such a socket
// now carries the name of its group.
func TestOwnerAppSharedCgroup(t *testing.T) {
	session := "user.slice/user-1000.slice/session-3.scope"
	for _, c := range []struct {
		name string
		o    sockets.Owner
		want string
	}{
		{"own scope", sockets.Owner{Name: "firefox", Unit: "app-gnome-firefox-123.scope", Procs: []string{"firefox", "Web Content"}}, "firefox"},
		{"shared, one program", sockets.Owner{Name: "login session", Unit: "session-3.scope", Cgroup: session, Shared: true, Procs: []string{"curl"}}, "curl"},
		{"login session", sockets.Owner{Name: "login session", Unit: "session-3.scope", Cgroup: session, Shared: true, Procs: []string{"sshd-session", "bash", "curl"}}, "group:login-session"},
		{"another login, same name", sockets.Owner{Name: "login session", Unit: "session-41.scope", Shared: true, Procs: []string{"bash", "curl"}}, "group:login-session"},
		{"shunt app rule with helpers", sockets.Owner{Name: "firefox", Unit: "shunt:app/r1", Shared: true, Procs: []string{"firefox", "Web Content", "Socket Process"}}, "group:shunt:app/r1"},
		{"shunt named group", sockets.Owner{Name: "brave", Unit: "shunt:g/work stuff", Shared: true, Procs: []string{"brave", "signal-desktop"}}, "group:shunt:g/work_stuff"},
		{"user manager", sockets.Owner{Unit: "user@1000.service", Shared: true, Procs: []string{"a", "b"}}, "group:user@1000"},
		{"no unit", sockets.Owner{Cgroup: "lxc.payload.box", Shared: true, Procs: []string{"a", "b"}}, "group:lxc.payload.box"},
		{"no unit, no path", sockets.Owner{Shared: true}, ""},
		{"unknown", sockets.Owner{}, ""},
	} {
		got := ownerApp(c.o)
		if got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
		if strings.ContainsAny(got, " \t\n") {
			t.Errorf("%s: %q has white space (event details are key=value words)", c.name, got)
		}
	}
	long := ownerApp(sockets.Owner{Unit: strings.Repeat("ä", 80) + ".service", Shared: true})
	if len(long) > len(groupPrefix)+64 || !strings.HasPrefix(long, groupPrefix+"ä") || strings.ContainsRune(long, '\uFFFD') {
		t.Errorf("long name: %q", long)
	}
}

// The whole way of lab R07: connections from a shared login session are
// learned for the group and a new destination after the learning phase is
// reported under the group's name.
func TestFirstSeenInSharedSession(t *testing.T) {
	now := time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)
	m := defense.NewManager(slog.New(slog.NewTextHandler(io.Discard, nil)), defense.WithClock(func() time.Time { return now }))
	defer m.Close()
	cfg := defense.DefaultConfig()
	cfg.Enabled = true
	m.Configure(cfg)
	m.SetNetwork("n", defense.ClassUnknown)
	app := ownerApp(sockets.Owner{Name: "login session", Unit: "session-7.scope", Shared: true, Procs: []string{"sshd-session", "bash", "labfs-curl"}})
	count := func() (n int, detail string) {
		for _, e := range m.Events(0).Events {
			if e.Kind == defense.KindFirstSeen {
				n++
				detail = e.Detail
			}
		}
		return
	}
	m.NoteConn(app, netip.MustParseAddrPort("198.18.1.1:80"), true) // starts the learning phase
	now = now.Add(11 * time.Minute)
	m.NoteConn(app, netip.MustParseAddrPort("198.18.2.1:80"), true)
	n, detail := count()
	if n != 1 || !strings.Contains(detail, "app=group:login-session ") {
		t.Fatalf("new destination from a shared session: %d events, detail %q", n, detail)
	}
	m.NoteConn(app, netip.MustParseAddrPort("198.18.2.1:80"), true)
	if n, _ := count(); n != 1 {
		t.Fatalf("known destination reported again: %d events", n)
	}
}

// tcpPacket builds an IPv4/TCP packet as the NFLOG rule hands it over.
func tcpPacket(src [4]byte, dport uint16, flags byte) []byte {
	p := make([]byte, 40)
	p[0], p[9] = 0x45, 6
	copy(p[12:16], src[:])
	copy(p[16:20], []byte{192, 0, 2, 50})
	p[20], p[21] = 0xc3, 0x50 // source port 50000
	p[22], p[23] = byte(dport>>8), byte(dport)
	p[32] = 5 << 4
	p[33] = flags
	return p
}

// The inbound packet log feeds new connections to real services into the
// brute-force counter; replies, tunnel peers and ports that are not real
// services do not count.
func TestDefenseLogPacketService(t *testing.T) {
	m := defense.NewManager(slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer m.Close()
	cfg := defense.DefaultConfig()
	cfg.Enabled = true
	cfg.DecoyPorts = nil
	cfg.Features[defense.FeatBrute] = defense.Feature{Watch: true}
	m.Configure(cfg)
	m.SetNetwork("n", defense.ClassUnknown)
	d := &Daemon{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	d.def.m = m
	st := &logState{listen: map[string]bool{"tcp/22": true, "tcp/631": true}, svc: map[int]string{22: "sshd"},
		tun: map[uint32]bool{9: true}, at: time.Now().Add(time.Hour)}
	feed := func(src [4]byte, port uint16, flags byte, dev uint32, n int) {
		for i := 0; i < n; i++ {
			pl := tcpPacket(src, port, flags)
			d.defenseLogPacket(st, nflog.Attribute{Payload: &pl, InDev: &dev})
		}
	}
	count := func() int {
		n := 0
		for _, e := range m.Events(0).Events {
			if e.Kind == defense.KindBruteService {
				n++
			}
		}
		return n
	}
	feed([4]byte{203, 0, 113, 5}, 22, 0x10, 2, 30)  // ACKs: replies to own connections
	feed([4]byte{203, 0, 113, 6}, 22, 0x02, 9, 30)  // through a tunnel
	feed([4]byte{203, 0, 113, 7}, 631, 0x02, 2, 30) // open, but not a service of the network
	if n := count(); n != 0 {
		t.Fatalf("%d brute_service events from replies, tunnel peers or other ports", n)
	}
	feed([4]byte{203, 0, 113, 8}, 22, 0x02, 2, 12)
	if n := count(); n != 1 {
		t.Fatalf("SYNs to sshd: %d events, want 1", n)
	}
}
