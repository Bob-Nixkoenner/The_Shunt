package winsplit

import (
	"fmt"
	"net/netip"
)

// guardRanges: every IPv4 address but dns (netsh takes ranges, no "not").
func guardRanges(dns netip.Addr) string {
	lo, hi := dns.Prev(), dns.Next()
	return fmt.Sprintf("0.0.0.0-%s,%s-255.255.255.255", lo, hi)
}
