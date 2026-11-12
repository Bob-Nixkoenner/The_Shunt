package defense

import (
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// DNS rebind check. The DNS proxy hands every answer (name, addresses) to
// Manager.Rebind. A public name that resolves to a private, loopback,
// link-local, CGNAT or unspecified address is the pattern DNS rebinding
// uses to reach devices behind the user's router (the browser's origin is
// the attacker's name, the address is the victim's). Names under local
// suffixes and names the user listed in defense.rebind_allow are exempt.
// The check runs only with defense.rebind_protect on and the dns_rebind
// feature watching; the answer is dropped only when that feature's Block
// switch is on, otherwise it is reported only.

const rebindCooldown = 10 * time.Minute

// localSuffixes are namespaces that are not public DNS; answers there may
// legitimately be private.
var localSuffixes = []string{
	"local", "lan", "home", "internal", "localdomain", "home.arpa", "intranet",
	"corp", "private", "localhost", "in-addr.arpa", "ip6.arpa", "test", "invalid",
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// RebindClass names the kind of non-public address ("" = a public one).
func RebindClass(a netip.Addr) string {
	a = a.Unmap()
	switch {
	case a.IsLoopback():
		return "loopback"
	case a.IsPrivate():
		return "private"
	case a.IsLinkLocalUnicast():
		return "link-local"
	case cgnat.Contains(a):
		return "cgnat"
	case a.IsUnspecified():
		return "unspecified"
	}
	return ""
}

func hasSuffix(name, suf string) bool { return name == suf || strings.HasSuffix(name, "."+suf) }

// rebindExempt: single-label, local-suffix or allow-listed names.
func rebindExempt(name string, allow []string) bool {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if !strings.Contains(name, ".") {
		return true
	}
	for _, s := range localSuffixes {
		if hasSuffix(name, s) {
			return true
		}
	}
	for _, a := range allow {
		a = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(a)), ".")
		if a != "" && hasSuffix(name, a) {
			return true
		}
	}
	return false
}

// Rebind is called by the DNS proxy for every answered A/AAAA set. It
// returns true when the answer must be dropped.
func (m *Manager) Rebind(name string, addrs []netip.Addr) (drop bool) {
	m.mu.Lock()
	on := m.cfg.RebindProtect
	allow := m.cfg.RebindAllow
	f := m.featureLocked(FeatDNSRebind)
	m.mu.Unlock()
	if !on || !f.Watch {
		return false
	}
	class := ""
	for _, a := range addrs {
		if c := RebindClass(a); c != "" {
			class = c
			break
		}
	}
	if class == "" || rebindExempt(name, allow) {
		return false
	}
	base := BaseDomain(name)
	now := m.now()
	m.dns.mu.Lock()
	if m.dns.rebound == nil {
		m.dns.rebound = map[string]time.Time{}
	}
	t, seen := m.dns.rebound[base]
	fire := !seen || now.Sub(t) >= rebindCooldown
	if fire && len(m.dns.rebound) < 256 {
		m.dns.rebound[base] = now
	}
	m.dns.mu.Unlock()
	if fire {
		act := "reported"
		if f.Block {
			act = "dropped"
		}
		m.Report(Event{Kind: KindDNSRebind, Severity: SevMedium, Proto: "udp", Port: 53,
			Detail: fmt.Sprintf("domain=%s class=%s action=%s", base, class, act)})
	}
	return f.Block
}
