package winsplit

import (
	"net"
	"net/netip"
	"os"
)

// TCPPortTaken reports whether another program has a TCP socket on port
// (IPv4 or IPv6, any address). On an error the port counts as taken: a
// decoy must never sit in front of a real service.
func TCPPortTaken(port int) bool {
	self := uint32(os.Getpid())
	for _, v6 := range []bool{false, true} {
		rs, err := rows(6, v6)
		if err != nil {
			return true
		}
		if PortTaken(rs, uint16(port), self) {
			return true
		}
	}
	return false
}

// InterfaceV4 returns the first global IPv4 address of the interface with
// index idx (invalid if none).
func InterfaceV4(idx uint32) netip.Addr {
	ifc, err := net.InterfaceByIndex(int(idx))
	if err != nil {
		return netip.Addr{}
	}
	as, err := ifc.Addrs()
	if err != nil {
		return netip.Addr{}
	}
	for _, a := range as {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(n.IP)
		if !ok {
			continue
		}
		if ip = ip.Unmap(); ip.Is4() && ip.IsGlobalUnicast() {
			return ip
		}
	}
	return netip.Addr{}
}
