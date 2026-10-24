// Package doh keeps browsers on the system resolver (The Shunt's DNS), so
// DNS follows the routes and the DNS filter applies: Firefox's canary domain
// and the well-known public DNS-over-HTTPS endpoints are answered NXDOMAIN.
package doh

import "strings"

// Canary tells Firefox that the network does not want DoH
// (https://support.mozilla.org/kb/canary-domain-use-application-dnsnet).
const Canary = "use-application-dns.net"

// Well-known public DoH endpoints. Answering NXDOMAIN for them makes
// browsers fall back to the system resolver, i.e. to us.
var Hosts = []string{
	"dns.google", "dns.google.com", "8888.google",
	"cloudflare-dns.com", "mozilla.cloudflare-dns.com", "chrome.cloudflare-dns.com",
	"one.one.one.one", "1dot1dot1dot1.cloudflare-dns.com", "security.cloudflare-dns.com", "family.cloudflare-dns.com",
	"dns.quad9.net", "dns9.quad9.net", "dns10.quad9.net", "dns11.quad9.net", "dns12.quad9.net",
	"doh.opendns.com", "doh.familyshield.opendns.com", "dns.umbrella.com",
	"dns.nextdns.io", "doh.cleanbrowsing.org",
	"dns.adguard.com", "dns.adguard-dns.com", "dns-unfiltered.adguard.com", "dns-family.adguard.com",
	"doh.mullvad.net", "dns.mullvad.net", "adblock.dns.mullvad.net", "base.dns.mullvad.net",
	"doh.dns.sb", "dns.controld.com", "freedns.controld.com",
	"doh.libredns.gr", "doh.applied-privacy.net", "dns.digitale-gesellschaft.ch",
	"dns.switch.ch", "doh.ffmuc.net", "dns3.digitalcourage.de", "dns.alidns.com", "doh.pub",
}

// Unwanted: answer name (lower case, no trailing dot) with NXDOMAIN. The
// canary always; the DoH endpoints when blockDoH (dns.allow_doh not set).
func Unwanted(name string, blockDoH bool) bool {
	if name == Canary {
		return true
	}
	if !blockDoH {
		return false
	}
	for _, d := range Hosts {
		if name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
}
