package wfp

import (
	"net/netip"
	"testing"
)

func TestExitFiltersOwnedAndTaken(t *testing.T) {
	owned := netip.MustParseAddrPort("127.0.0.1:1080")
	taken := netip.MustParseAddrPort("[::1]:1081")
	torSocks := netip.MustParseAddrPort("127.0.0.1:50001")
	fs, err := ExitFilters([]ExitGuard{
		{Addr: owned},
		{Addr: taken, Taken: true},
		{Addr: torSocks, Owners: []string{`C:\Shunt\tor\tor.exe`}},
	})
	if err != nil {
		t.Fatal(err)
	}
	type key struct {
		layer  ExitLayer
		addr   netip.AddrPort
		permit bool
		app    string
	}
	got := map[key]ExitFilter{}
	for i, f := range fs {
		if f.Index != uint32(i) {
			t.Errorf("filter %d has index %d", i, f.Index)
		}
		if f.V6 != f.Addr.Addr().Is6() {
			t.Errorf("%s: V6 = %v", f.Name, f.V6)
		}
		if f.Permit && f.Weight <= exitWeightBlock || !f.Permit && f.Weight != exitWeightBlock {
			t.Errorf("%s: weight %d", f.Name, f.Weight)
		}
		if !f.Permit && f.App != "" {
			t.Errorf("%s: a block bound to a program", f.Name)
		}
		got[key{f.Layer, f.Addr, f.Permit, f.App}] = f
	}
	want := []key{
		// owned exit: only the service accepts, nobody else; connecting stays open
		{ExitLayerAccept, owned, true, ""},
		{ExitLayerAccept, owned, false, ""},
		// taken exit: the squatter cannot accept, and connecting is blocked
		{ExitLayerAccept, taken, true, ""},
		{ExitLayerAccept, taken, false, ""},
		{ExitLayerConnect, taken, true, ""},
		{ExitLayerConnect, taken, false, ""},
		// tor's SOCKS port: only tor.exe accepts
		{ExitLayerAccept, torSocks, true, `C:\Shunt\tor\tor.exe`},
		{ExitLayerAccept, torSocks, false, ""},
	}
	for _, w := range want {
		if _, ok := got[w]; !ok {
			t.Errorf("missing filter %+v", w)
		}
	}
	if len(fs) != len(want) {
		t.Errorf("%d filters, want %d: %+v", len(fs), len(want), fs)
	}
	for _, f := range fs {
		if f.Layer == ExitLayerConnect && f.Addr != taken {
			t.Errorf("connect filter for an address the service holds: %s (would cut off the exit's users)", f.Name)
		}
		if f.Addr == torSocks && f.Permit && f.App == "" {
			t.Errorf("the service may accept on tor's port: %s", f.Name)
		}
	}
}

func TestExitFiltersSkipAndBound(t *testing.T) {
	fs, err := ExitFilters([]ExitGuard{{}, {Addr: netip.MustParseAddrPort("127.0.0.1:0")},
		{Addr: netip.MustParseAddrPort("[::ffff:127.0.0.1]:1080")}})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 2 || fs[0].V6 || fs[0].Addr != netip.MustParseAddrPort("127.0.0.1:1080") {
		t.Fatalf("filters = %+v", fs)
	}
	if fs, _ := ExitFilters(nil); len(fs) != 0 {
		t.Errorf("no guards gave %d filters", len(fs))
	}
	var many []ExitGuard
	for p := uint16(1); p <= ExitMaxIndex/4+1; p++ {
		many = append(many, ExitGuard{Addr: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), p), Taken: true})
	}
	if _, err := ExitFilters(many); err == nil {
		t.Error("more filters than keys accepted")
	}
}
