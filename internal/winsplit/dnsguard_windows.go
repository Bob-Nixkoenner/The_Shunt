package winsplit

import "net/netip"

// The DNS guard stops Windows' DNS client from asking the DNS servers of the
// real network behind our back. With "smart multi-homed name resolution"
// it sends every query to the DNS servers of all adapters at once, the
// router's on the local network included: that query does not take a route
// of ours (the router is on-link), so the network sees every name even when
// the app's traffic goes through a tunnel.
//
// Windows Firewall blocks port 53 for the DNS client service (Dnscache),
// except towards our adapter's DNS address. Apps that resolve on their own
// and The Shunt's direct DNS (the service's own sockets) are not affected.
//
// Names also leave as local broadcasts when DNS has no answer (typos, bare
// host names, WPAD): LLMNR and mDNS (the DNS client, UDP 5355/5353) and
// NetBIOS (the kernel, UDP 137) ask everybody on the local network. Those
// are blocked as well; local devices are still found by their DNS name from
// the router (the direct route asks it, see Engine.SetSystemDNS).
// The rules are removed when the service stops on purpose; after a crash
// they stay and name resolution waits for the service, like the kill switch.

const guardPrefix = "Shunt DNS "

var guardRules = []string{"udp v4", "tcp v4", "udp v6", "tcp v6", "llmnr", "mdns", "netbios"}

// EnableDNSGuard installs the rules; dns is the adapter's DNS address.
func EnableDNSGuard(dns netip.Addr) error {
	DisableDNSGuard() // from an earlier run
	dnsRule := func(proto, remote string) []string {
		return []string{"service=dnscache", "protocol=" + proto, "remoteport=53", "remoteip=" + remote}
	}
	for _, r := range []struct {
		name   string
		params []string
	}{
		{"udp v4", dnsRule("udp", guardRanges(dns))},
		{"tcp v4", dnsRule("tcp", guardRanges(dns))},
		{"udp v6", dnsRule("udp", allIPv6)},
		{"tcp v6", dnsRule("tcp", allIPv6)},
		{"llmnr", []string{"service=dnscache", "protocol=udp", "remoteport=5355"}},
		{"mdns", []string{"service=dnscache", "protocol=udp", "remoteport=5353"}},
		{"netbios", []string{"program=System", "protocol=udp", "remoteport=137"}},
	} {
		if err := fw(append([]string{"firewall", "add", "rule", "name=" + guardPrefix + r.name, "dir=out", "action=block", "enable=yes", "profile=any"}, r.params...)...); err != nil {
			DisableDNSGuard()
			return err
		}
	}
	return nil
}

// DisableDNSGuard removes the rules. Safe to call when nothing is installed.
func DisableDNSGuard() {
	for _, n := range guardRules {
		_ = fw("firewall", "delete", "rule", "name="+guardPrefix+n)
	}
}

// allIPv6: netsh refuses "::/0".
const allIPv6 = "::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
