package windefense

import (
	"net/netip"
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/Bob-Nixkoenner/the_shunt/internal/defense"
	"github.com/Bob-Nixkoenner/the_shunt/internal/netdetect"
)

func TestLimitKeepsOnlyWatchers(t *testing.T) {
	c := defense.DefaultConfig()
	c.Enabled = true
	for _, n := range defense.AllFeatures {
		c.Features[n] = defense.Feature{Watch: true, Block: true}
	}
	want := map[string]bool{}
	for _, n := range Features {
		want[n] = true
	}
	blockOK := map[string]bool{}
	for _, n := range BlockFeatures {
		blockOK[n] = true
	}
	for _, canBlock := range []bool{false, true} {
		l := Limit(c, canBlock)
		for _, n := range defense.AllFeatures {
			f := l.Features[n]
			if f.Block != (canBlock && blockOK[n]) {
				t.Errorf("canBlock=%v %s: Block=%v", canBlock, n, f.Block)
			}
			if f.Watch != want[n] {
				t.Errorf("%s: Watch=%v want %v", n, f.Watch, want[n])
			}
		}
		if len(l.DecoyPorts) == 0 {
			t.Error("decoy ports must stay")
		}
		if !canBlock && (l.UnsafeBlock == nil || *l.UnsafeBlock) {
			t.Error("without firewall the unsafe-network block must be off")
		}
		if canBlock && l.UnsafeBlock != nil {
			t.Error("with firewall the user's unsafe_block stays")
		}
	}
	// no decoys, no trigger: no block either
	c.Features[defense.FeatDecoy] = defense.Feature{}
	if l := Limit(c, true); l.Features[defense.FeatScan].Block || l.UnsafeBlock == nil || *l.UnsafeBlock {
		t.Error("blocking without decoys")
	}
	c.Features[defense.FeatDecoy] = defense.Feature{Watch: true}
	c.DecoyPorts = nil
	if l := Limit(c, true); l.Features[defense.FeatReputation].Block {
		t.Error("blocking without decoy ports")
	}
}

func TestApplyAndNetwork(t *testing.T) {
	r := New(t.TempDir(), nil, nil, nil)
	defer r.Close()
	c, err := config.Parse("[daemon]\ndefault_route = \"direct\"\n[defense]\nenabled = true\n")
	if err != nil {
		t.Fatal(err)
	}
	r.Apply(c)
	r.Network(netdetect.Info{Iface: "Ethernet", SSID: "x", GatewayIP: "192.0.2.1"})
	st := r.Status()
	if !st.Enabled {
		t.Fatal("defense should be enabled")
	}
	if st.Unsupported == "" {
		t.Error("status must say what is missing")
	}
	if b := r.Brief(); b == nil {
		t.Error("brief must exist while on")
	}
}

func TestObserverReputationReports(t *testing.T) {
	r := New(t.TempDir(), nil, nil, nil)
	defer r.Close()
	cfg := defense.DefaultConfig()
	cfg.Enabled = true
	r.M.Configure(Limit(cfg, false))
	r.M.SetNetwork("k", defense.ClassUnsafe)
	o := r.Observer()
	// a private target is ignored, a public one without a list hit is quiet
	o.NewConn("Chrome.exe", 6, netip.MustParseAddrPort("10.0.0.5:443"))
	o.NewConn("Chrome.exe", 6, netip.MustParseAddrPort("198.51.100.7:443"))
	o.DNSQuery("chrome.exe", "example.org.", "A")
}

func TestNetKeyIgnoresGatewayMAC(t *testing.T) {
	a := NetKey(netdetect.Info{Iface: "i", SSID: "s", GatewayIP: "g", GatewayMAC: "aa"})
	b := NetKey(netdetect.Info{Iface: "i", SSID: "s", GatewayIP: "g", GatewayMAC: "bb"})
	if a != b {
		t.Error("key must not depend on the gateway MAC")
	}
}
