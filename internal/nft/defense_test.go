package nft

import (
	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/Bob-Nixkoenner/the_shunt/internal/engine"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestRenderDefense(t *testing.T) {
	s := RenderDefense(DefenseOpts{Log: true})
	for _, want := range []string{"table inet shunt_defense", "delete table inet shunt_defense", "set ban4", "set ban6",
		"ip saddr @ban4 counter drop", "ip6 saddr @ban6 counter drop", "log group 5302", "ip saddr @never4 return"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in\n%s", want, s)
		}
	}
	if strings.Contains(RenderDefense(DefenseOpts{}), "log group") {
		t.Error("log rule without Log")
	}
	// never must be checked before ban
	if strings.Index(s, "@never4") > strings.Index(s, "@ban4") {
		t.Error("never after ban")
	}
}

func TestBanScripts(t *testing.T) {
	a := netip.MustParseAddr("192.0.2.9")
	if got := BanScript(a, 90*time.Second); got != "add element inet shunt_defense ban4 { 192.0.2.9 timeout 90s }\n" {
		t.Fatal(got)
	}
	if got := BanScript(netip.MustParseAddr("::ffff:192.0.2.9"), 0); !strings.Contains(got, "ban4 { 192.0.2.9 timeout 1s }") {
		t.Fatal(got)
	}
	if got := UnbanScript(netip.MustParseAddr("2001:db8::7")); !strings.Contains(got, "delete element inet shunt_defense ban6 { 2001:db8::7 }") {
		t.Fatal(got)
	}
}

func TestNeverScript(t *testing.T) {
	s := NeverScript([]netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("192.0.2.5/32"),
		netip.MustParsePrefix("198.51.100.1/32"), netip.MustParsePrefix("2001:db8::/32"),
	})
	if !strings.Contains(s, "never4 { 192.0.2.0/24, 198.51.100.1/32 }") || !strings.Contains(s, "never6 { 2001:db8::/32 }") {
		t.Fatal(s)
	}
	if !strings.HasPrefix(s, "flush set inet shunt_defense never4\nflush set inet shunt_defense never6\n") {
		t.Fatal(s)
	}
}

func TestDecoyPortsScript(t *testing.T) {
	if got := DecoyPortsScript([]int{22, 80}); got != "flush set inet shunt add element inet shunt decoy_ports { 22, 80 }\n" && !strings.Contains(got, "decoy_ports { 22, 80 }") {
		t.Fatal(got)
	}
	if strings.Contains(DecoyPortsScript(nil), "add element") {
		t.Fatal("empty list adds")
	}
}

func TestInboundLetsDecoysThrough(t *testing.T) {
	in := &engine.Inbound{Mode: config.InboundClosed, Uplinks: []string{"wlan0"}}
	l, err := inboundLines(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(l, "\n"), "tcp dport @decoy_ports accept") {
		t.Fatal(l)
	}
}
