package defense

import "net/netip"

// Windows neighbour states (NL_NEIGHBOR_STATE) that carry a usable MAC.
const (
	nlUnreachable = 0
	nlIncomplete  = 1
)

// neighEntry turns one row of the system's ARP/NDP table into the pair the
// gateway watch takes. ok is false for rows without a usable address:
// unreachable or incomplete entries, a MAC that is not 6 bytes, an
// invalid IP. The MAC comes back as lower-case "aa:bb:cc:dd:ee:ff".
func neighEntry(ip netip.Addr, mac []byte, state int) (netip.Addr, string, bool) {
	if !ip.IsValid() || state == nlUnreachable || state == nlIncomplete || len(mac) != 6 {
		return netip.Addr{}, "", false
	}
	const hex = "0123456789abcdef"
	b := make([]byte, 0, 17)
	for i, x := range mac {
		if i > 0 {
			b = append(b, ':')
		}
		b = append(b, hex[x>>4], hex[x&15])
	}
	return ip.Unmap(), string(b), true
}
