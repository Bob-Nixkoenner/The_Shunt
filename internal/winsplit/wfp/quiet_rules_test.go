package wfp

import (
	"testing"
)

func TestQuietRulesOrder(t *testing.T) {
	r := QuietRules()
	seenDrop := false
	var drops, permits int
	for _, x := range r {
		if x.Permit {
			permits++
			if seenDrop {
				t.Fatal("permit after a drop")
			}
			continue
		}
		seenDrop = true
		drops++
	}
	if permits != 7 { // DHCP, DHCPv6, 5 x ND
		t.Errorf("permits = %d", permits)
	}
	if want := 2*(len(QuietUDPPorts)+len(QuietTCPPorts)) + 4; drops != want { // ports per family, multicast v4/v6, 255.255.255.255, broadcast type
		t.Errorf("drops = %d, want %d", drops, want)
	}
	has := func(p string) bool {
		for _, x := range r {
			if !x.Permit && x.Prefix.IsValid() && x.Prefix.String() == p {
				return true
			}
		}
		return false
	}
	for _, p := range []string{"224.0.0.0/4", "ff00::/8", "255.255.255.255/32"} {
		if !has(p) {
			t.Errorf("missing drop %s", p)
		}
	}
	// subnet broadcasts by address type, without knowing the network (D05)
	var bc []QuietRule
	for _, x := range r {
		if x.DestBroadcast {
			bc = append(bc, x)
		}
	}
	if len(bc) != 1 || bc[0].V6 || bc[0].Permit || bc[0].Proto != 0 || bc[0].Prefix.IsValid() {
		t.Errorf("broadcast-type drop: %+v", bc)
	}
	// the same set every time: nothing depends on the interfaces
	if a, b := QuietFilters(), QuietFilters(); len(a) != len(b) {
		t.Errorf("filter set not stable")
	}
}

func TestQuietPorts(t *testing.T) {
	need := map[uint16]bool{137: false, 138: false, 1900: false, 3702: false, 5353: false, 5355: false}
	for _, x := range QuietRules() {
		if !x.Permit && x.Proto == 17 {
			if _, ok := need[x.RemotePort]; ok && x.V6 {
				need[x.RemotePort] = true
			}
		}
	}
	for p, ok := range need {
		if !ok {
			t.Errorf("UDP %d not dropped (IPv6)", p)
		}
	}
	for _, x := range QuietRules() {
		if !x.Permit && x.Proto == 17 && (x.RemotePort == 67 || x.RemotePort == 547) {
			t.Errorf("DHCP dropped: %+v", x)
		}
	}
}

// Every rule sits at ALE connect and at outbound transport (ALE only sees
// the first packet of a flow), each persistent and as a boot-time copy under
// the same index; indexes are unique per kind and below QuietMaxIndex.
func TestQuietFilters(t *testing.T) {
	rules := QuietRules()
	fs := QuietFilters()
	if len(fs) != len(rules)*len(QuietLayers)*2 {
		t.Fatalf("%d filters for %d rules", len(fs), len(rules))
	}
	type key struct {
		boot bool
		idx  uint32
	}
	seen := map[key]bool{}
	perLayer := map[QuietLayer]int{}
	for _, f := range fs {
		k := key{f.Boot, f.Index}
		if seen[k] {
			t.Errorf("index %d (boot=%v) twice", f.Index, f.Boot)
		}
		seen[k] = true
		if f.Index >= QuietMaxIndex {
			t.Errorf("index %d over %d", f.Index, QuietMaxIndex)
		}
		if f.Weight != QuietWeight(f.Rule, f.Boot) {
			t.Errorf("%+v: weight %d", f, f.Weight)
		}
		if f.Name == "" || len(f.Name) > 80 {
			t.Errorf("name %q", f.Name)
		}
		if !f.Boot {
			perLayer[f.Layer]++
		}
	}
	for _, l := range QuietLayers {
		if perLayer[l] != len(rules) {
			t.Errorf("layer %v: %d persistent filters, want %d", l, perLayer[l], len(rules))
		}
	}
	// every persistent filter has a boot-time twin with the same rule and layer
	for i := 0; i+1 < len(fs); i += 2 {
		p, b := fs[i], fs[i+1]
		if p.Boot || !b.Boot || p.Index != b.Index || p.Layer != b.Layer || p.Rule != b.Rule {
			t.Errorf("pair %d: %+v / %+v", i, p, b)
		}
	}
	// the counts the lab check (test/lab/wd/d05-check.ps1) expects
	if n := len(fs) / 2; n != 58 {
		t.Errorf("persistent quiet filters = %d (update d05-check.ps1 and the lab notes)", n)
	}
}

// The boot-time copies share the default sublayer with the kill switch's
// boot-time copies (LAN permit 11, DHCP/ND permit 12): the drops must weigh
// more than those, the own DHCP/ND permits more than the drops.
func TestQuietWeightBoot(t *testing.T) {
	const ksLAN, ksDHCP = 11, 12
	for _, boot := range []bool{false, true} {
		for _, r := range QuietRules() {
			w := QuietWeight(r, boot)
			if w > 15 {
				t.Fatalf("weight %d out of range", w)
			}
			if r.Permit && w <= QuietWeight(QuietRule{}, boot) {
				t.Errorf("boot=%v: permit %+v not above the drops", boot, r)
			}
			if boot && !r.Permit && (w <= ksLAN || w <= ksDHCP) {
				t.Errorf("boot drop %+v weight %d not above the kill switch permits", r, w)
			}
		}
	}
}
