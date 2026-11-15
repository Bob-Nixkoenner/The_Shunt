// Package winsplit holds the Windows parts of the per-app split (see
// docs/WINDOWS.md): which process owns a connection, and sockets that go
// out through the physical interface instead of the Shunt TUN (wintun).
// Table parsing is platform-neutral so it can be tested anywhere.
package winsplit

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// Row is one entry of an owner table (GetExtendedTcpTable/-UdpTable with
// *_OWNER_PID): the local end of a socket and its process.
type Row struct {
	Local netip.AddrPort
	PID   uint32
}

var errShort = errors.New("owner table: truncated")

// port: the tables keep ports in network byte order in the low 16 bits of a DWORD.
func port(b []byte) uint16 { return binary.BigEndian.Uint16(b[:2]) }

// parseTable reads a MIB_*TABLE_OWNER_PID buffer: DWORD count, then rows
// of rowSize bytes; addr/port/pid are byte offsets in a row, v6 says
// whether the address is 16 bytes (else a 4-byte IPv4 address).
func parseTable(b []byte, rowSize, addrOff, portOff, pidOff int, v6 bool) ([]Row, error) {
	if len(b) < 4 {
		return nil, errShort
	}
	n := int(binary.LittleEndian.Uint32(b))
	b = b[4:]
	if len(b) < n*rowSize {
		return nil, errShort
	}
	rows := make([]Row, 0, n)
	for i := 0; i < n; i++ {
		r := b[i*rowSize : (i+1)*rowSize]
		var a netip.Addr
		if v6 {
			a = netip.AddrFrom16([16]byte(r[addrOff : addrOff+16]))
		} else {
			a = netip.AddrFrom4([4]byte(r[addrOff : addrOff+4]))
		}
		rows = append(rows, Row{Local: netip.AddrPortFrom(a, port(r[portOff:])), PID: binary.LittleEndian.Uint32(r[pidOff:])})
	}
	return rows, nil
}

// Row layouts (iphlpapi, tcpmib.h / udpmib.h).
func parseTCP4(b []byte) ([]Row, error) { return parseTable(b, 24, 4, 8, 20, false) } // MIB_TCPROW_OWNER_PID
func parseTCP6(b []byte) ([]Row, error) { return parseTable(b, 56, 0, 20, 52, true) } // MIB_TCP6ROW_OWNER_PID
func parseUDP4(b []byte) ([]Row, error) { return parseTable(b, 12, 0, 4, 8, false) }  // MIB_UDPROW_OWNER_PID
func parseUDP6(b []byte) ([]Row, error) { return parseTable(b, 28, 0, 20, 24, true) } // MIB_UDP6ROW_OWNER_PID

// find returns the PID of the socket bound to local; a socket bound to the
// unspecified address (0.0.0.0 / ::, typical for UDP) matches any address
// with that port. Two different programs on the same address and port
// (SO_REUSEADDR) make the owner unknown (report L-08): the first row must not
// lend its route to another program's packets.
func find(rows []Row, local netip.AddrPort) (uint32, bool) {
	var exact, wildcard uint32
	nExact, nWild := 0, 0
	for _, r := range rows {
		if r.Local.Port() != local.Port() {
			continue
		}
		if r.Local.Addr() == local.Addr() {
			if nExact == 0 || r.PID != exact {
				nExact++
			}
			exact = r.PID
			continue
		}
		if r.Local.Addr().IsUnspecified() && r.Local.Addr().Is4() == local.Addr().Is4() {
			if nWild == 0 || r.PID != wildcard {
				nWild++
			}
			wildcard = r.PID
		}
	}
	switch {
	case nExact == 1:
		return exact, true
	case nExact > 1:
		return 0, false
	case nWild == 1:
		return wildcard, true
	}
	return 0, false
}

// PortTaken reports whether another program holds TCP port: a row with
// that local port owned by a process other than self. Rows without a
// process (TIME_WAIT of closed connections, PID 0) do not count, so a
// decoy can take its port again after a network change.
func PortTaken(rows []Row, port uint16, self uint32) bool {
	for _, r := range rows {
		if r.Local.Port() == port && r.PID != 0 && r.PID != self {
			return true
		}
	}
	return false
}
