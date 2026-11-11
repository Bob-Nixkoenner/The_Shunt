package defense

import (
	"encoding/binary"
	"net/netip"
)

// ParseLoggedPacket reads the source address, protocol and destination port
// from the start of an IP packet (what an nft "log group" rule hands over).
// It returns ok=false for anything that is not the first fragment of a
// TCP or UDP packet.
func ParseLoggedPacket(p []byte) (src netip.Addr, proto string, port int, ok bool) {
	if len(p) < 1 {
		return
	}
	var l4 []byte
	var pr byte
	switch p[0] >> 4 {
	case 4:
		if len(p) < 20 {
			return
		}
		ihl := int(p[0]&0xf) * 4
		if ihl < 20 || len(p) < ihl+4 || binary.BigEndian.Uint16(p[6:8])&0x1fff != 0 {
			return
		}
		src, _ = netip.AddrFromSlice(p[12:16])
		pr, l4 = p[9], p[ihl:]
	case 6:
		if len(p) < 44 {
			return
		}
		src, _ = netip.AddrFromSlice(p[8:24])
		pr, l4 = p[6], p[40:] // extension headers are not followed: such packets are skipped
	default:
		return
	}
	switch pr {
	case 6:
		proto = "tcp"
	case 17:
		proto = "udp"
	default:
		return netip.Addr{}, "", 0, false
	}
	if len(l4) < 4 || !src.IsValid() {
		return netip.Addr{}, "", 0, false
	}
	return src, proto, int(binary.BigEndian.Uint16(l4[2:4])), true
}
