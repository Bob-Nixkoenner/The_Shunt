package nft

import (
	"net/netip"
	"regexp"
	"strings"
	"testing"
)

// The counting table must only count: no verdict, no mark, no NAT, nothing
// that could change where a packet goes or whether it goes at all.
func TestRenderWaysOnlyCounts(t *testing.T) {
	s, err := RenderWays(Ways{
		TunnelIfaces: []string{"sh-home", "sh-vps"},
		Endpoints:    []netip.Addr{netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr("2001:db8::7"), netip.MustParseAddr("203.0.113.7")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(s, "table inet "+Table+" ") || strings.Contains(s, "inet "+Table+"\n") {
		t.Fatalf("touches the main table:\n%s", s)
	}
	forbidden := regexp.MustCompile(`\b(accept|drop|reject|return|jump|goto|queue|masquerade|redirect|dnat|snat|tproxy|notrack|delete|set|flowtable)\b`)
	rules := 0
	for _, l := range strings.Split(strings.TrimSpace(s), "\n") {
		if !strings.HasPrefix(l, "add ") && !strings.HasPrefix(l, "flush chain ") {
			t.Errorf("unexpected line %q", l)
		}
		if !strings.Contains(l, " "+WaysTable+" ") && !strings.HasSuffix(l, " "+WaysTable) {
			t.Errorf("line outside %s: %q", WaysTable, l)
		}
		if !strings.HasPrefix(l, "add rule ") {
			continue
		}
		rules++
		if m := forbidden.FindString(l); m != "" {
			t.Errorf("rule has %q: %s", m, l)
		}
		if !regexp.MustCompile(`counter name (direct|lan)_(rx|tx)$`).MatchString(l) {
			t.Errorf("rule does not end in a named counter: %s", l)
		}
	}
	if rules != 8 {
		t.Errorf("%d rules, want 8 (2 families x 2 directions x 2 classes)", rules)
	}
	// the base chains themselves only accept (no drop policy)
	for _, l := range strings.Split(s, "\n") {
		if strings.HasPrefix(l, "add chain ") && !strings.Contains(l, "policy accept;") {
			t.Errorf("chain without policy accept: %s", l)
		}
	}
	for _, want := range []string{
		`oifname != { "lo", "sh-`,
		"meta mark != 0x5300ff",
		"fib saddr type local",
		"ip daddr != { 203.0.113.7 }",
		"ip saddr != { 203.0.113.7 }",
		"ip6 saddr != { 2001:db8::7 }",
		"hook postrouting priority filter + 10",
		"hook input priority filter + 10",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in\n%s", want, s)
		}
	}
	// the counters are added, never reset or replaced
	if strings.Contains(s, "reset") || strings.Contains(s, "delete table") {
		t.Errorf("script resets the counters:\n%s", s)
	}
}

func TestRenderWaysNoEndpoints(t *testing.T) {
	s, err := RenderWays(Ways{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(s, "{  }") || strings.Contains(s, "{ }") {
		t.Errorf("empty set rendered:\n%s", s)
	}
	if !strings.Contains(s, `oifname != { "lo" }`) {
		t.Errorf("loopback not excluded:\n%s", s)
	}
}

func TestRenderWaysRejectsBadIface(t *testing.T) {
	if _, err := RenderWays(Ways{TunnelIfaces: []string{`wg0" accept`}}); err == nil {
		t.Fatal("unsafe interface name accepted")
	}
}

func TestParseWays(t *testing.T) {
	js := `{"nftables": [{"metainfo": {"version": "1.0.9", "json_schema_version": 1}},
	{"table": {"family": "inet", "name": "shunt_ways", "handle": 9}},
	{"counter": {"family": "inet", "name": "direct_rx", "table": "shunt_ways", "handle": 1, "packets": 10, "bytes": 1000}},
	{"counter": {"family": "inet", "name": "direct_tx", "table": "shunt_ways", "handle": 2, "packets": 5, "bytes": 500}},
	{"counter": {"family": "inet", "name": "lan_rx", "table": "shunt_ways", "handle": 3, "packets": 2, "bytes": 20}},
	{"counter": {"family": "inet", "name": "lan_tx", "table": "shunt_ways", "handle": 4, "packets": 1, "bytes": 18446744073709551615}},
	{"counter": {"family": "inet", "name": "other", "table": "shunt_ways", "handle": 5, "packets": 1, "bytes": 7}},
	{"chain": {"family": "inet", "table": "shunt_ways", "name": "out", "handle": 6}}]}`
	w, err := ParseWays([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	if w.DirectRX != 1000 || w.DirectTX != 500 || w.LANRX != 20 {
		t.Errorf("got %+v", w)
	}
	if w.LANTX < 0 {
		t.Errorf("huge counter turned negative: %d", w.LANTX)
	}
	// incomplete or foreign tables are an error, not zero
	if _, err := ParseWays([]byte(`{"nftables": [{"counter": {"family": "inet", "name": "direct_rx", "table": "shunt_ways", "bytes": 1}}]}`)); err == nil {
		t.Error("incomplete table accepted")
	}
	if _, err := ParseWays([]byte(strings.ReplaceAll(js, `"shunt_ways"`, `"other"`))); err == nil {
		t.Error("foreign table accepted")
	}
	if _, err := ParseWays([]byte("nft: no such table")); err == nil {
		t.Error("garbage accepted")
	}
}
