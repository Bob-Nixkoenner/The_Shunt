//go:build linux

package mobile

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/defense"
)

type namePlatform struct{ fakePlatform }

func (*namePlatform) AppName(uid int) string {
	if uid == 10123 {
		return "org.example.app"
	}
	return ""
}

func events(t *testing.T, st *defenseState) []defense.Event {
	t.Helper()
	return st.m.Events(0).Events
}

func TestDefenseOffByDefaultAndAndroidFeaturesOnly(t *testing.T) {
	st, obs := newDefense(t.TempDir(), &namePlatform{})
	defer st.m.Close()
	obs.NewConn("10123", 6, netip.MustParseAddrPort("203.0.113.9:443"))
	if n := len(events(t, st)); n != 0 {
		t.Fatalf("disabled defense reported %d events", n)
	}
	// features that cannot work here stay off, and Block is ignored
	st.configure(defenseInput{Enabled: true, Features: map[string]defense.Feature{
		defense.FeatDecoy: {Watch: true, Block: true}, defense.FeatBeacon: {Watch: true, Block: true}}})
	s := st.m.Status()
	if s.Config.Features[defense.FeatDecoy].Watch || s.Config.Features[defense.FeatBeacon].Block {
		t.Fatalf("config not clamped: %+v", s.Config.Features)
	}
	if !s.Config.Features[defense.FeatBeacon].Watch || len(s.Decoys) != 0 {
		t.Fatalf("beacon should watch, no decoys: %+v %v", s.Config.Features[defense.FeatBeacon], s.Decoys)
	}
}

func TestDefenseReputationHitNamesApp(t *testing.T) {
	dir := t.TempDir()
	st, obs := newDefense(dir, &namePlatform{})
	defer st.m.Close()
	st.configure(defenseInput{Enabled: true})
	// a downloaded list in the cache directory
	src := defense.DefaultSources[0]
	if err := os.WriteFile(defense.CacheFile(dir, src), []byte("203.0.113.9\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if n := st.reload(); n < 1 {
		t.Fatalf("reload loaded %d lists", n)
	}
	obs.NewConn("10123", 6, netip.MustParseAddrPort("203.0.113.9:443"))
	obs.NewConn("10123", 6, netip.MustParseAddrPort("198.51.100.1:443")) // not listed
	ev := events(t, st)
	if len(ev) != 1 || ev[0].Kind != defense.KindReputation || ev[0].Src != "203.0.113.9" ||
		!strings.Contains(ev[0].Detail, "app=org.example.app") {
		t.Fatalf("events: %+v", ev)
	}
	var srcs []map[string]string
	if err := json.Unmarshal([]byte(((&Engine{def: st}).DefenseSources())), &srcs); err != nil || len(srcs) != 2 ||
		srcs[0]["file"] != filepath.Base(defense.CacheFile("", src)) {
		t.Fatalf("sources: %v %v", srcs, err)
	}
}

func TestDefenseDNSTunnelFromObserver(t *testing.T) {
	st, obs := newDefense("", nil)
	defer st.m.Close()
	st.configure(defenseInput{Enabled: true})
	for i := 0; i < 60; i++ {
		obs.DNSQuery("10123", strings.Repeat("a1b2c3d4e5f6", 4)+string(rune('a'+i%26))+string(rune('a'+i/26))+".evil.example.", "TXT")
	}
	for _, e := range events(t, st) {
		if e.Kind == defense.KindDNSTunnel {
			return
		}
	}
	t.Fatalf("no dns_tunnel event: %+v", events(t, st))
}

func TestDefenseStatusJSON(t *testing.T) {
	st, _ := newDefense("", nil)
	defer st.m.Close()
	st.configure(defenseInput{Enabled: true})
	st.m.SetNetwork("k", "trusted")
	e := &Engine{def: st}
	var d defenseStatus
	if err := json.Unmarshal([]byte(e.defenseJSON()), &d); err != nil {
		t.Fatal(err)
	}
	if !d.Enabled || d.Class != defense.ClassSafe || d.Level != defense.LevelQuiet {
		t.Fatalf("%+v", d)
	}
}
