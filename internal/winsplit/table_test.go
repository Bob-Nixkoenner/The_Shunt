package winsplit

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestParseTables(t *testing.T) {
	// MIB_TCPTABLE_OWNER_PID with two rows
	tcp4 := make([]byte, 4+2*24)
	binary.LittleEndian.PutUint32(tcp4, 2)
	row := func(i int, ip [4]byte, p uint16, pid uint32) {
		r := tcp4[4+i*24:]
		binary.LittleEndian.PutUint32(r, 5) // state ESTABLISHED
		copy(r[4:], ip[:])
		binary.BigEndian.PutUint16(r[8:], p)
		binary.LittleEndian.PutUint32(r[20:], pid)
	}
	row(0, [4]byte{10, 111, 0, 2}, 50123, 4242)
	row(1, [4]byte{0, 0, 0, 0}, 443, 7)
	rows, err := parseTCP4(tcp4)
	if err != nil || len(rows) != 2 {
		t.Fatal(rows, err)
	}
	if pid, ok := find(rows, netip.MustParseAddrPort("10.111.0.2:50123")); !ok || pid != 4242 {
		t.Errorf("exact: %d %v", pid, ok)
	}
	if pid, ok := find(rows, netip.MustParseAddrPort("10.111.0.2:443")); !ok || pid != 7 {
		t.Errorf("wildcard: %d %v", pid, ok)
	}
	if _, ok := find(rows, netip.MustParseAddrPort("10.111.0.2:1")); ok {
		t.Error("unknown port found")
	}
	if _, err := parseTCP4(tcp4[:30]); err == nil {
		t.Error("truncated table accepted")
	}

	// MIB_UDP6TABLE_OWNER_PID, one row
	udp6 := make([]byte, 4+28)
	binary.LittleEndian.PutUint32(udp6, 1)
	a := netip.MustParseAddr("fd11:5ee:bad:c0de::2").As16()
	copy(udp6[4:], a[:])
	binary.BigEndian.PutUint16(udp6[4+20:], 5353)
	binary.LittleEndian.PutUint32(udp6[4+24:], 99)
	rows, err = parseUDP6(udp6)
	if err != nil || len(rows) != 1 || rows[0].PID != 99 || rows[0].Local != netip.MustParseAddrPort("[fd11:5ee:bad:c0de::2]:5353") {
		t.Fatal(rows, err)
	}
}
