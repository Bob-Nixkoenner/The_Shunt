package defense

import (
	"net/netip"
	"testing"
)

func TestRebindClass(t *testing.T) {
	for a, want := range map[string]string{
		"10.1.2.3": "private", "172.16.0.9": "private", "192.168.1.1": "private", "127.0.0.1": "loopback",
		"::1": "loopback", "169.254.1.1": "link-local", "fe80::1": "link-local", "fd00::5": "private",
		"100.64.0.1": "cgnat", "100.127.255.1": "cgnat", "0.0.0.0": "unspecified",
		"192.0.2.1": "", "198.51.100.7": "", "203.0.113.5": "", "2001:db8::1": "", "100.128.0.1": "",
		"::ffff:10.0.0.1": "private",
	} {
		if got := RebindClass(netip.MustParseAddr(a)); got != want {
			t.Errorf("%s: %q want %q", a, got, want)
		}
	}
}

func TestRebindManager(t *testing.T) {
	priv := []netip.Addr{netip.MustParseAddr("192.168.5.5")}
	pub := []netip.Addr{netip.MustParseAddr("192.0.2.1")}
	off, _ := enabledManager(t)
	if off.Rebind("evil.example.net", priv) {
		t.Fatal("must be off by default")
	}
	if n, _ := countKind(off, KindDNSRebind); n != 0 {
		t.Fatal("event while off")
	}

	m, clk := enabledManager(t, func(c *Config) {
		c.RebindProtect = true
		c.RebindAllow = []string{"home.example.org"}
	})
	if m.Rebind("evil.example.net", priv) {
		t.Fatal("report only without Block")
	}
	n, ev := countKind(m, KindDNSRebind)
	if n != 1 || ev.Severity != SevMedium || ev.Detail != "domain=example.net class=private action=reported" {
		t.Fatalf("%d %+v", n, ev)
	}
	m.Rebind("other.example.net", priv) // same base: cooldown
	if n, _ := countKind(m, KindDNSRebind); n != 1 {
		t.Fatal("cooldown")
	}
	clk.Add(rebindCooldown)
	m.Rebind("evil.example.net", priv)
	if n, _ := countKind(m, KindDNSRebind); n != 2 {
		t.Fatal("after cooldown")
	}
	for _, c := range []struct {
		name  string
		addrs []netip.Addr
	}{
		{"fine.example.net", pub}, {"nas.home.example.org", priv}, {"printer.local", priv}, {"router", priv},
		{"x.lan", priv}, {"1.2.3.10.in-addr.arpa", priv},
	} {
		before, _ := countKind(m, KindDNSRebind)
		if m.Rebind(c.name, c.addrs) {
			t.Errorf("%s dropped", c.name)
		}
		if after, _ := countKind(m, KindDNSRebind); after != before {
			t.Errorf("%s reported", c.name)
		}
	}

	b, _ := enabledManager(t, func(c *Config) {
		c.RebindProtect = true
		c.Features[FeatDNSRebind] = Feature{Watch: true, Block: true}
	})
	if !b.Rebind("evil.example.net", priv) {
		t.Fatal("Block must drop")
	}
	if _, ev := countKind(b, KindDNSRebind); ev.Detail != "domain=example.net class=private action=dropped" {
		t.Fatalf("%+v", ev)
	}
	if b.Rebind("fine.example.net", pub) {
		t.Fatal("public answer dropped")
	}
}
