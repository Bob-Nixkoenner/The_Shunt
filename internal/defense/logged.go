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

// ParseConnPacket reads the endpoints of a TCP packet (what the output
// chain's log rule hands over: the SYN of a new outgoing connection). It
// returns ok=false for anything that is not the first fragment of a TCP
// packet.
func ParseConnPacket(p []byte) (src, dst netip.AddrPort, ok bool) {
	if len(p) < 1 {
		return
	}
	var l4 []byte
	var a, b netip.Addr
	switch p[0] >> 4 {
	case 4:
		if len(p) < 20 {
			return
		}
		ihl := int(p[0]&0xf) * 4
		if ihl < 20 || len(p) < ihl+4 || binary.BigEndian.Uint16(p[6:8])&0x1fff != 0 || p[9] != 6 {
			return
		}
		a, _ = netip.AddrFromSlice(p[12:16])
		b, _ = netip.AddrFromSlice(p[16:20])
		l4 = p[ihl:]
	case 6:
		if len(p) < 44 || p[6] != 6 {
			return
		}
		a, _ = netip.AddrFromSlice(p[8:24])
		b, _ = netip.AddrFromSlice(p[24:40])
		l4 = p[40:]
	default:
		return
	}
	if !a.IsValid() || !b.IsValid() || len(l4) < 4 {
		return
	}
	return netip.AddrPortFrom(a, binary.BigEndian.Uint16(l4[0:2])), netip.AddrPortFrom(b, binary.BigEndian.Uint16(l4[2:4])), true
}

// IsTCPReply reports whether the logged packet is a TCP segment that can only
// belong to a connection somebody opened earlier: ACK or RST set (SYN-ACK,
// plain ACK, RST). A connection attempt is a bare SYN. After a restart of the
// daemon or a lost connection-tracking entry such answers to our own outgoing
// connections reach the log as "new"; they are no scan and no brute force.
// Limit: an attacker who sends bare ACK or RST packets is not counted either
// (such packets reveal no port and are dropped by the kernel anyway).
func IsTCPReply(p []byte) bool {
	if len(p) < 1 {
		return false
	}
	var l4 []byte
	switch p[0] >> 4 {
	case 4:
		ihl := int(p[0]&0xf) * 4
		if ihl < 20 || len(p) < ihl+14 || p[9] != 6 || binary.BigEndian.Uint16(p[6:8])&0x1fff != 0 {
			return false
		}
		l4 = p[ihl:]
	case 6:
		if len(p) < 54 || p[6] != 6 {
			return false
		}
		l4 = p[40:]
	default:
		return false
	}
	return l4[13]&(0x10|0x04) != 0 // ACK | RST
}
