package defense

import (
	"encoding/binary"
	"net/netip"
)

// NamesFromIPv6 is NamesFromIPv4 for IPv6: mDNS (ff02::fb) and LLMNR
// (ff02::1:3) announcements, UDP on port 5353 or 5355, read from one packet
// starting at the IPv6 header. Only packets whose next header is UDP are
// read (extension headers are skipped by the sensor's filter, not parsed).
func NamesFromIPv6(pkt []byte) []NameClaim {
	if len(pkt) < 48 || pkt[0]>>4 != 6 || pkt[6] != 17 {
		return nil
	}
	src := netip.AddrFrom16([16]byte(pkt[8:24]))
	sp, dp := binary.BigEndian.Uint16(pkt[40:]), binary.BigEndian.Uint16(pkt[42:])
	end := len(pkt)
	if ulen := int(binary.BigEndian.Uint16(pkt[44:])); ulen >= 8 && 40+ulen < end {
		end = 40 + ulen
	}
	pl := pkt[48:end]
	switch {
	case dp == 5353 || sp == 5353:
		return ParseMDNSNames(pl, src, false)
	case dp == 5355 || sp == 5355:
		return ParseMDNSNames(pl, src, true)
	}
	return nil
}
