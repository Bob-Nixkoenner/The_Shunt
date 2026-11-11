package daemon

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
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
