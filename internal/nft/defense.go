package nft

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// DecoySet is the set in the main table that lists the decoy ports (only
// present when the inbound protection is on).
const DecoySet = "decoy_ports"

// DefenseLogGroup is the NFLOG group that gets the first packets of new
// inbound connections (scan and brute-force observation).
const DefenseLogGroup = 5302

// DefenseConnLogGroup is the NFLOG group that gets the SYN of every new
// outgoing TCP connection (beacon and first-contact detection without
// polling the socket list).
const DefenseConnLogGroup = 5303

// connLogExemptPorts: NTP, DNS, DHCP/DHCPv6 (the same ports the beacon
// detection skips anyway).
const connLogExemptPorts = "53, 67, 68, 123, 546, 547"

// DefenseOpts tunes RenderDefense.
type DefenseOpts struct {
	// Log sends new inbound TCP/UDP connections (rate limited) to
	// DefenseLogGroup so shuntd can count them per source.
	Log bool
	// ConnLog sends the SYN of new outgoing TCP connections (rate limited,
	// 64 bytes of each packet, never loopback, never to the never sets) to
	// DefenseConnLogGroup.
	ConnLog bool
}

// RenderDefense renders the defense table: timed block sets for IPv4 and
// IPv6 sources, never-block sets, and the input chain that drops blocked
// sources. Bans are added and removed with BanScript/UnbanScript without
// replacing the table; the never sets with NeverScript.
func RenderDefense(o DefenseOpts) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	replaceHeader(&b, DefenseTable)
	w("table inet %s {", DefenseTable)
	w("\tset ban4 {\n\t\ttype ipv4_addr; flags interval, timeout;\n\t}")
	w("\tset ban6 {\n\t\ttype ipv6_addr; flags interval, timeout;\n\t}")
	w("\tset never4 {\n\t\ttype ipv4_addr; flags interval;\n\t}")
	w("\tset never6 {\n\t\ttype ipv6_addr; flags interval;\n\t}")
	w("\tchain input {")
	w("\t\ttype filter hook input priority -10; policy accept;")
	w("\t\tiifname \"lo\" return")
	w("\t\tip saddr @never4 return")
	w("\t\tip6 saddr @never6 return")
	w("\t\tip saddr @ban4 counter drop")
	w("\t\tip6 saddr @ban6 counter drop")
	if o.Log {
		w("\t\tct state new meta l4proto { tcp, udp } limit rate 300/second burst 100 packets log group %d snaplen 128", DefenseLogGroup)
	}
	w("\t}")
	if o.ConnLog {
		w("\tchain output {")
		w("\t\ttype filter hook output priority -10; policy accept;")
		w("\t\toifname \"lo\" return")
		w("\t\tip daddr @never4 return")
		w("\t\tip6 daddr @never6 return")
		w("\t\ttcp flags & (syn | ack) == syn tcp dport != { %s } limit rate 100/second burst 50 packets log group %d snaplen 64", connLogExemptPorts, DefenseConnLogGroup)
		w("\t}")
	}
	w("}")
	return b.String()
}

// DeleteDefenseScript removes the defense table.
func DeleteDefenseScript() string { return DeleteScript(DefenseTable) }

func setFor(a netip.Addr) string {
	if a.Is4() {
		return "ban4"
	}
	return "ban6"
}

// BanScript blocks src for d (at least one second).
func BanScript(src netip.Addr, d time.Duration) string {
	src = src.Unmap()
	secs := int(d / time.Second)
	if secs < 1 {
		secs = 1
	}
	return fmt.Sprintf("add element inet %s %s { %s timeout %ds }\n", DefenseTable, setFor(src), src, secs)
}

// UnbanScript lifts the block on src. nft refuses to delete an element that
// is not in the set, so the add comes first (a no-op for an existing one).
func UnbanScript(src netip.Addr) string {
	src = src.Unmap()
	return fmt.Sprintf("add element inet %s %s { %s timeout 1s }\ndelete element inet %s %s { %s }\n",
		DefenseTable, setFor(src), src, DefenseTable, setFor(src), src)
}

// NeverScript replaces the never-block sets by p (overlapping prefixes are
// merged away; nft rejects overlapping intervals).
func NeverScript(p []netip.Prefix) string {
	var b strings.Builder
	fmt.Fprintf(&b, "flush set inet %s never4\nflush set inet %s never6\n", DefenseTable, DefenseTable)
	for _, fam := range []struct {
		set string
		v4  bool
	}{{"never4", true}, {"never6", false}} {
		var l []string
		for _, x := range dropCovered(p) {
			if x.Addr().Is4() == fam.v4 {
				l = append(l, x.String())
			}
		}
		if len(l) > 0 {
			fmt.Fprintf(&b, "add element inet %s %s { %s }\n", DefenseTable, fam.set, strings.Join(l, ", "))
		}
	}
	return b.String()
}

// dropCovered masks, sorts and removes duplicates and prefixes inside
// another prefix.
func dropCovered(in []netip.Prefix) []netip.Prefix {
	var l []netip.Prefix
	for _, x := range in {
		if x.IsValid() {
			l = append(l, x.Masked())
		}
	}
	sort.Slice(l, func(i, j int) bool {
		if c := l[i].Addr().Compare(l[j].Addr()); c != 0 {
			return c < 0
		}
		return l[i].Bits() < l[j].Bits()
	})
	var out []netip.Prefix
	for _, x := range l {
		if n := len(out); n > 0 && out[n-1].Contains(x.Addr()) && out[n-1].Bits() <= x.Bits() {
			continue
		}
		out = append(out, x)
	}
	return out
}

// DecoyPortsScript replaces the contents of the decoy set in the main table.
func DecoyPortsScript(ports []int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "flush set inet %s %s\n", Table, DecoySet)
	if len(ports) > 0 {
		l := make([]string, len(ports))
		for i, p := range ports {
			l[i] = fmt.Sprint(p)
		}
		fmt.Fprintf(&b, "add element inet %s %s { %s }\n", Table, DecoySet, strings.Join(l, ", "))
	}
	return b.String()
}

// BanRangeScript blocks a whole range (a /24 or /64 the defense collected
// single sources into) for d. The ban sets are interval sets.
func BanRangeScript(p netip.Prefix, d time.Duration) string {
	secs := int(d / time.Second)
	if secs < 1 {
		secs = 1
	}
	return fmt.Sprintf("add element inet %s %s { %s timeout %ds }\n", DefenseTable, setFor(p.Addr()), p.Masked(), secs)
}

// UnbanRangeScript lifts the block on a range.
func UnbanRangeScript(p netip.Prefix) string {
	return fmt.Sprintf("add element inet %s %s { %s timeout 1s }\ndelete element inet %s %s { %s }\n",
		DefenseTable, setFor(p.Addr()), p.Masked(), DefenseTable, setFor(p.Addr()), p.Masked())
}
