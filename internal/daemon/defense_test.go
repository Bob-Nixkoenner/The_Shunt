package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/Bob-Nixkoenner/the_shunt/internal/defense"
	"github.com/Bob-Nixkoenner/the_shunt/internal/netdetect"
)

func TestDefenseRoutes(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	d := &Daemon{Log: log, cfg: &config.Config{Networks: []config.Network{{Name: "home", SSID: []string{"x"}, Class: "trusted"}}}}
	d.def.m = defense.NewManager(log)
	defer d.def.m.Close()
	mux := http.NewServeMux()
	d.defenseRoutes(mux)

	get := func(path string, v any) {
		t.Helper()
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != 200 {
			t.Fatalf("%s: %d %s", path, rec.Code, rec.Body)
		}
		if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
			t.Fatal(err)
		}
	}
	var st defense.Status
	get("/v1/defense", &st)
	if st.Enabled || st.Class != defense.ClassPublic {
		t.Fatalf("%+v", st)
	}
	d.def.m.Configure(defense.Config{Enabled: true, Features: map[string]defense.Feature{}, BanSeconds: 60})
	d.def.m.SetNetwork("k", defense.ClassTrusted)
	var ev defense.EventsResponse
	get("/v1/defense/events?since=0", &ev)
	if len(ev.Events) != 1 || ev.Events[0].Kind != defense.KindNetEnter || strings.Contains(ev.Events[0].Detail, "k") && ev.Events[0].Detail != "class=trusted" {
		t.Fatalf("%+v", ev)
	}
	get("/v1/defense/events?since=1", &ev)
	if len(ev.Events) != 0 {
		t.Fatal("since")
	}
	for i, s := range []string{"192.0.2.7", "198.51.100.1", "192.0.2.7"} {
		d.def.m.Report(defense.Event{Kind: defense.KindDecoyHit, Src: s, Port: 20 + i})
	}
	get("/v1/defense/events?src=192.0.2.7", &ev)
	if len(ev.Events) != 2 || ev.Events[0].Port != 20 || ev.Events[1].Port != 22 {
		t.Fatalf("src filter: %+v", ev)
	}
	get("/v1/defense/events?src=::ffff:192.0.2.7", &ev)
	if len(ev.Events) != 2 {
		t.Fatalf("mapped src: %+v", ev)
	}
	var rp defense.ReportsResponse
	get("/v1/defense/reports", &rp)
	if len(rp.Reports) != 1 || rp.Reports[0].Counts[defense.KindDecoyHit] != 3 {
		t.Fatalf("reports: %+v", rp)
	}
	rp = defense.ReportsResponse{}
	get("/v1/defense/reports?export=1", &rp)
	if !rp.Export || rp.Current != "" {
		t.Fatalf("export: %+v", rp)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/v1/defense/events?src=x", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad src: %d", rec.Code)
	}
	if b := d.defenseBrief(); b == nil || b.Class != defense.ClassTrusted {
		t.Fatalf("%+v", b)
	}
	// changing things needs the manage permission: no peer, no change
	for _, p := range []string{"/v1/defense/config", "/v1/defense/unban", "/v1/defense/ban"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest("POST", p, strings.NewReader("{}")))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s without permission: %d", p, rec.Code)
		}
	}
}

func TestDefenseNetworkKeyAndClass(t *testing.T) {
	info := netdetect.Info{Iface: "wlan0", SSID: "x", GatewayMAC: "02:00:00:00:00:01"}
	k := defNetKey(info)
	if len(k) != 16 || strings.Contains(k, "x") && strings.Contains(k, "wlan") {
		t.Fatal(k)
	}
	if defNetKey(info) != k || defNetKey(netdetect.Info{Iface: "wlan0", SSID: "y"}) == k {
		t.Fatal("key must be stable and per network")
	}
	c := &config.Config{Networks: []config.Network{{Name: "home", SSID: []string{"x"}, Class: "trusted"}}}
	if c.NetClass(info) != defense.ClassTrusted || c.NetClass(netdetect.Info{SSID: "other"}) != defense.ClassPublic {
		t.Fatal("class")
	}
}

// A failed start (no plan yet, e.g. config error) must not start the loops
// and must not crash downloadClient.
func TestDefenseStartFailureNoLoops(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	d := &Daemon{Log: log, ConfigPath: t.TempDir() + "/shunt.toml", cfg: &config.Config{}}
	ctx, cancel := context.WithCancel(context.Background())
	d.startDefense(ctx)
	if d.downloadClient() == nil {
		t.Fatal("nil client")
	}
	if d.def.loops.Load() {
		t.Fatal("loops started before a successful start")
	}
	if st := d.defenseStatus(); st.Enabled {
		t.Fatal("defense must stay off")
	}
	d.startDefenseLoops(ctx)
	d.startDefenseLoops(ctx) // idempotent
	cancel()
	time.Sleep(50 * time.Millisecond)
}

func TestInvalidDefenseConfigRejected(t *testing.T) {
	for _, bad := range []string{"[defense]\nenabled = true\ndns_probe = \"x\"\n", "[defense]\nenabled = true\ndhcp_probe = \"x\"\n"} {
		if _, err := config.Parse(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

// A new gateway MAC behind the same address is no network change: no new
// net_enter, no counter reset; interface, SSID or gateway address do change it.
func TestDefNetKeyIgnoresGatewayMAC(t *testing.T) {
	a := netdetect.Info{Iface: "eth0", SSID: "net", GatewayIP: "192.0.2.1", GatewayMAC: "02:00:00:00:00:01"}
	b := a
	b.GatewayMAC = "02:00:00:00:00:02"
	if defNetKey(a) != defNetKey(b) {
		t.Fatal("gateway MAC changes the key")
	}
	for _, c := range []netdetect.Info{{Iface: "wlan0", SSID: "net", GatewayIP: "192.0.2.1"}, {Iface: "eth0", SSID: "other", GatewayIP: "192.0.2.1"}, {Iface: "eth0", SSID: "net", GatewayIP: "192.0.2.254"}} {
		if defNetKey(a) == defNetKey(c) {
			t.Fatalf("key unchanged for %+v", c)
		}
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := defense.NewManager(log)
	defer m.Close()
	m.Configure(defense.Config{Enabled: true, Features: map[string]defense.Feature{}, BanSeconds: 60})
	for i := 0; i < 5; i++ {
		m.SetNetwork(defNetKey(a), defense.ClassPublic)
		m.Report(defense.Event{Kind: defense.KindARP, Severity: defense.SevHigh, Detail: "x"})
		m.SetNetwork(defNetKey(b), defense.ClassPublic)
	}
	st := m.Status()
	enters := 0
	for _, e := range m.Events(0).Events {
		if e.Kind == defense.KindNetEnter {
			enters++
		}
	}
	if enters != 1 || st.Counts[defense.KindNetEnter] != 1 || st.Counts[defense.KindARP] != 5 || st.Heat == 0 {
		t.Fatalf("enters=%d counts=%v heat=%d", enters, st.Counts, st.Heat)
	}
}

func TestEndpointPrefixes(t *testing.T) {
	got := endpointPrefixes([]string{"203.0.113.9:51820", "[2001:db8::1]:51820", "203.0.113.9:1194", " 198.51.100.4 ",
		"relay fra", "vpn.example.net:1194", "", "127.0.0.1:9050", "0.0.0.0:0", "[::ffff:192.0.2.77]:443"})
	want := "[192.0.2.77/32 198.51.100.4/32 203.0.113.9/32 2001:db8::1/128]"
	if fmt.Sprint(got) != want {
		t.Fatalf("got %v, want %s", got, want)
	}
	var many []string
	for i := 0; i < 300; i++ {
		many = append(many, fmt.Sprintf("198.51.%d.%d:51820", i/250, i%250+1))
	}
	if n := len(endpointPrefixes(many)); n != maxTunnelNever {
		t.Fatalf("cap: %d", n)
	}
}

// Tunnel peers join gateway and DNS on the never-block list: neither a
// manual block nor a finding can cut the tunnel.
func TestTunnelPeersNeverBlocked(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	d := &Daemon{Log: log}
	d.def.m = defense.NewManager(log)
	defer d.def.m.Close()
	cfg := defense.DefaultConfig()
	cfg.Enabled = true
	d.def.m.Configure(cfg)

	d.defenseNeverPart(&d.def.neverNet, []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")})
	d.defenseTunnelPeers([]string{"203.0.113.9:51820"})
	for _, a := range []string{"192.0.2.1", "203.0.113.9"} {
		if err := d.def.m.Ban(a); !errors.Is(err, defense.ErrNeverBan) {
			t.Fatalf("%s: %v", a, err)
		}
	}
	// the peer moved: the old address is free again, the gateway stays
	d.defenseTunnelPeers([]string{"198.51.100.4:51820"})
	if err := d.def.m.Ban("203.0.113.9"); err != nil {
		t.Fatalf("old endpoint still protected: %v", err)
	}
	for _, a := range []string{"192.0.2.1", "198.51.100.4"} {
		if err := d.def.m.Ban(a); !errors.Is(err, defense.ErrNeverBan) {
			t.Fatalf("%s: %v", a, err)
		}
	}
	// tunnels gone: only the network part is left
	d.defenseTunnelPeers(nil)
	if err := d.def.m.Ban("198.51.100.4"); err != nil {
		t.Fatalf("endpoint of a removed tunnel still protected: %v", err)
	}
}

// Lab H04, second part: the automatic block spares a tunnel endpoint too
// (here the one that needs no handshake: an address on a bad list with
// blocking on). The finding is still reported.
func TestTunnelPeerNotBlockedAutomatically(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	d := &Daemon{Log: log}
	d.def.m = defense.NewManager(log)
	defer d.def.m.Close()
	cfg := defense.DefaultConfig()
	cfg.Enabled = true
	cfg.Features[defense.FeatDecoy] = defense.Feature{}
	cfg.Features[defense.FeatReputation] = defense.Feature{Watch: true, Block: true}
	d.def.m.Configure(cfg)
	endpoint, other := netip.MustParseAddr("203.0.113.9"), netip.MustParseAddr("198.51.100.5")
	d.def.m.Reputation().SetList("feodo", []netip.Prefix{netip.PrefixFrom(endpoint, 32), netip.PrefixFrom(other, 32)}, time.Time{})

	d.defenseTunnelPeers([]string{"203.0.113.9:51820"})
	d.def.m.Observe(endpoint, 22, "tcp", true)
	st := d.def.m.Status()
	if len(st.Bans) != 0 || st.Counts[defense.KindReputation] != 1 {
		t.Fatalf("tunnel endpoint on a bad list: bans %+v, reported %d", st.Bans, st.Counts[defense.KindReputation])
	}
	d.def.m.Observe(other, 22, "tcp", true) // control: any other listed address is blocked
	if bans := d.def.m.Status().Bans; len(bans) != 1 || bans[0].Src != other.String() {
		t.Fatalf("control: %+v", bans)
	}
	// the tunnel is gone: the address is treated like any other
	d.defenseTunnelPeers(nil)
	d.def.m.Observe(endpoint, 22, "tcp", true)
	if bans := d.def.m.Status().Bans; len(bans) != 2 {
		t.Fatalf("former endpoint still spared: %+v", bans)
	}
}
