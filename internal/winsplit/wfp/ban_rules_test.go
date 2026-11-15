package wfp

import (
	"errors"
	"net/netip"
	"testing"
)

func TestBanFixedRules(t *testing.T) {
	r := BanFixedRules()
	if len(r) > banFixed {
		t.Fatalf("%d fixed rules, room for %d", len(r), banFixed)
	}
	var lo4, lo6, dhcp, dhcp6, nd bool
	for i, x := range r {
		if !x.Permit || x.Weight != BanWeightFixed || x.Index != uint32(i) {
			t.Errorf("%+v", x)
		}
		switch {
		case x.Prefix.String() == "127.0.0.0/8" && !x.V6:
			lo4 = true
		case x.Prefix.String() == "::1/128" && x.V6:
			lo6 = true
		case x.Proto == 17 && x.LocalPort == 68 && !x.V6:
			dhcp = true
		case x.Proto == 17 && x.LocalPort == 546 && x.V6:
			dhcp6 = true
		case x.Proto == 58 && x.V6 && x.LocalPort >= 133 && x.LocalPort <= 137:
			nd = true
		}
	}
	if !lo4 || !lo6 || !dhcp || !dhcp6 || !nd {
		t.Errorf("missing fixed permit: lo4=%v lo6=%v dhcp=%v dhcp6=%v nd=%v", lo4, lo6, dhcp, dhcp6, nd)
	}
}

// Every permit (fixed, never-list) weighs more than every block: a range
// ban that covers the gateway leaves the gateway open.
func TestBanWeights(t *testing.T) {
	never, _ := NormNever([]netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")})
	for _, p := range append(BanFixedRules(), BanNeverRules(never)...) {
		if p.Weight <= BanWeightBlock || p.Weight > 15 {
			t.Errorf("permit %+v weight %d not above the blocks (%d)", p, p.Weight, BanWeightBlock)
		}
	}
	b := BanFilter(netip.MustParsePrefix("192.0.2.0/24"), 0)
	if b.Permit || b.Weight != BanWeightBlock {
		t.Errorf("%+v", b)
	}
}

func TestNormNever(t *testing.T) {
	in := []netip.Prefix{
		netip.MustParsePrefix("192.0.2.1/32"),
		netip.MustParsePrefix("::ffff:192.0.2.1/128"), // the same, mapped
		netip.MustParsePrefix("2001:db8::53/128"),
		netip.MustParsePrefix("198.51.100.7/24"), // masked
		{},
	}
	out, err := NormNever(in)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.1/32", "198.51.100.0/24", "2001:db8::53/128"}
	if len(out) != len(want) {
		t.Fatalf("%v", out)
	}
	for i := range want {
		if out[i].String() != want[i] {
			t.Errorf("%d: %s want %s", i, out[i], want[i])
		}
	}
	r := BanNeverRules(out)
	for i, x := range r {
		if !x.Permit || x.Index != banFixed+uint32(i) || x.V6 != out[i].Addr().Is6() {
			t.Errorf("%+v", x)
		}
	}
	var many []netip.Prefix
	for i := 0; i <= BanMaxNever; i++ {
		many = append(many, netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}), 32))
	}
	if _, err := NormNever(many); err == nil {
		t.Error("too long a never-list must fail (no bans then)")
	}
}

func TestCheckBan(t *testing.T) {
	ok := map[string]string{
		"192.0.2.7/32":            "192.0.2.7/32",
		"192.0.2.7/24":            "192.0.2.0/24",
		"::ffff:192.0.2.7/120":    "192.0.2.0/24",
		"2001:db8:1:2::5/64":      "2001:db8:1:2::/64",
		"10.20.30.0/16":           "10.20.0.0/16",
		"2001:db8::/32":           "2001:db8::/32",
		"fe80::1/128":             "fe80::1/128",
		"100.64.0.1/32":           "100.64.0.1/32",
		"::ffff:198.51.100.9/128": "198.51.100.9/32",
	}
	for in, want := range ok {
		p, err := CheckBan(netip.MustParsePrefix(in))
		if err != nil || p.String() != want {
			t.Errorf("%s: %v %v (want %s)", in, p, err, want)
		}
	}
	bad := map[string]error{
		"0.0.0.0/0":          ErrBanTooWide,
		"10.0.0.0/8":         ErrBanTooWide,
		"::/0":               ErrBanTooWide,
		"2001:db8::/16":      ErrBanTooWide,
		"0.0.0.0/32":         ErrBanAddress,
		"127.0.0.1/32":       ErrBanAddress,
		"::1/128":            ErrBanAddress,
		"::/128":             ErrBanAddress,
		"224.0.0.1/32":       ErrBanAddress,
		"ff02::1/128":        ErrBanAddress,
		"255.255.255.255/32": ErrBanAddress,
	}
	for in, want := range bad {
		if _, err := CheckBan(netip.MustParsePrefix(in)); !errors.Is(err, want) {
			t.Errorf("%s: %v, want %v", in, err, want)
		}
	}
	if p, err := BanPrefix("192.0.2.9"); err != nil || p.String() != "192.0.2.9/32" {
		t.Errorf("%v %v", p, err)
	}
	if p, err := BanPrefix("2001:db8::9"); err != nil || p.String() != "2001:db8::9/128" {
		t.Errorf("%v %v", p, err)
	}
	if _, err := BanPrefix("10.0.0.0/4"); err == nil {
		t.Error("wide range must fail")
	}
	if _, err := BanPrefix("not an address"); err == nil {
		t.Error("garbage must fail")
	}
}

// The gateway and the DNS servers can never be blocked one by one; a range
// around them can (the permit keeps them open).
func TestNeverHit(t *testing.T) {
	never, _ := NormNever([]netip.Prefix{
		netip.MustParsePrefix("192.168.1.1/32"),
		netip.MustParsePrefix("2001:db8::1/128"),
		netip.MustParsePrefix("198.51.100.0/24"),
	})
	for _, s := range []string{"192.168.1.1/32", "2001:db8::1/128", "198.51.100.7/32", "198.51.100.0/24"} {
		if !NeverHit(never, netip.MustParsePrefix(s)) {
			t.Errorf("%s must be refused", s)
		}
	}
	for _, s := range []string{"192.168.1.2/32", "192.168.1.0/24", "2001:db8::/64", "198.51.0.0/16"} {
		if NeverHit(never, netip.MustParsePrefix(s)) {
			t.Errorf("%s must be allowed", s)
		}
	}
}

func TestBanTable(t *testing.T) {
	var tab BanTable
	a := netip.MustParsePrefix("192.0.2.1/32")
	b := netip.MustParsePrefix("192.0.2.2/32")
	sa, isNew, err := tab.Slot(a)
	if err != nil || !isNew || sa != 0 {
		t.Fatal(sa, isNew, err)
	}
	if s, isNew, _ := tab.Slot(a); isNew || s != sa {
		t.Fatal("same ban twice must keep its slot")
	}
	sb, _, _ := tab.Slot(b)
	if sb == sa {
		t.Fatal("slots must differ")
	}
	if s, ok := tab.Release(a); !ok || s != sa {
		t.Fatal("release")
	}
	if _, ok := tab.Release(a); ok {
		t.Fatal("double release")
	}
	c := netip.MustParsePrefix("192.0.2.3/32")
	if s, _, _ := tab.Slot(c); s != sa {
		t.Errorf("freed slot not reused: %d", s)
	}
	tab.Reset()
	for i := 0; i < BanMaxBans; i++ {
		p := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}), 32)
		s, _, err := tab.Slot(p)
		if err != nil {
			t.Fatal(i, err)
		}
		if f := BanFilter(p, s); f.Index >= BanMaxIndex || f.Index < banFixed+BanMaxNever {
			t.Fatalf("index %d outside the ban room", f.Index)
		}
	}
	if _, _, err := tab.Slot(netip.MustParsePrefix("203.0.113.1/32")); !errors.Is(err, ErrBanFull) {
		t.Errorf("cap: %v", err)
	}
	if tab.Len() != BanMaxBans || len(tab.All()) != BanMaxBans {
		t.Error("len")
	}
}

func TestBanPrefixRefusesLoopback(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "::1", "0.0.0.0", "224.0.0.251"} {
		if _, err := BanPrefix(s); err == nil {
			t.Errorf("%s must be refused", s)
		}
	}
}
