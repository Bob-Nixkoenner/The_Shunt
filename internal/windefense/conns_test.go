package windefense

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/defense"
)

func row4(state uint32, la string, lp uint16, ra string, rp uint16, pid uint32) []byte {
	b := make([]byte, 24)
	binary.LittleEndian.PutUint32(b, state)
	copy(b[4:], netip.MustParseAddr(la).AsSlice())
	binary.BigEndian.PutUint16(b[8:], lp)
	copy(b[12:], netip.MustParseAddr(ra).AsSlice())
	binary.BigEndian.PutUint16(b[16:], rp)
	binary.LittleEndian.PutUint32(b[20:], pid)
	return b
}

func table(n int, rows ...[]byte) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(n))
	for _, r := range rows {
		b = append(b, r...)
	}
	return b
}

func TestParseTCP4(t *testing.T) {
	b := table(2, row4(5, "10.0.0.5", 50000, "93.184.216.34", 443, 1234), row4(2, "0.0.0.0", 80, "0.0.0.0", 0, 4))
	c := ParseTCP4(b)
	if len(c) != 2 || c[0].State != 5 || c[0].PID != 1234 || c[0].Remote != netip.MustParseAddrPort("93.184.216.34:443") ||
		c[0].Local != netip.MustParseAddrPort("10.0.0.5:50000") || c[1].State != 2 {
		t.Fatalf("%+v", c)
	}
	// a count larger than the buffer is cut, a short buffer gives nothing
	if got := ParseTCP4(table(9, row4(5, "1.1.1.1", 1, "2.2.2.2", 2, 3))); len(got) != 1 {
		t.Fatal(len(got))
	}
	if len(ParseTCP4(nil)) != 0 || len(ParseTCP4([]byte{1})) != 0 {
		t.Fatal("short")
	}
}

func TestParseTCP6(t *testing.T) {
	r := make([]byte, 56)
	copy(r[0:], netip.MustParseAddr("2001:db8::1").AsSlice())
	binary.BigEndian.PutUint16(r[20:], 51000)
	copy(r[24:], netip.MustParseAddr("2001:db8::2").AsSlice())
	binary.BigEndian.PutUint16(r[44:], 443)
	binary.LittleEndian.PutUint32(r[48:], 5)
	binary.LittleEndian.PutUint32(r[52:], 77)
	c := ParseTCP6(table(1, r))
	if len(c) != 1 || c[0].PID != 77 || c[0].State != 5 || c[0].Remote != netip.MustParseAddrPort("[2001:db8::2]:443") {
		t.Fatalf("%+v", c)
	}
}

func TestPollerNamesAndFreshness(t *testing.T) {
	m := defense.NewManager(nil)
	defer m.Close()
	cfg := defense.DefaultConfig()
	cfg.Enabled = true
	cfg.Features[defense.FeatFirstSeen] = defense.Feature{Watch: true}
	m.Configure(cfg)
	var rows []TCPConn
	d1 := netip.MustParseAddrPort("203.0.113.9:443")
	d2 := netip.MustParseAddrPort("203.0.113.10:443")
	rows = []TCPConn{
		{State: tcpEstablished, Local: netip.MustParseAddrPort("10.0.0.5:50000"), Remote: d1, PID: 100},
		{State: tcpListen, Local: netip.MustParseAddrPort("0.0.0.0:8080"), PID: 100},
		{State: tcpEstablished, Local: netip.MustParseAddrPort("10.0.0.5:8080"), Remote: netip.MustParseAddrPort("10.0.0.9:1111"), PID: 100}, // incoming to a listener
		{State: 6, Local: netip.MustParseAddrPort("10.0.0.5:50001"), Remote: d2, PID: 100},                                                  // time wait
	}
	lists := 0
	names := 0
	p := newConnPoller(m, func() ([]TCPConn, error) { lists++; return rows, nil },
		func(pid uint32) string { names++; return `C:\Prog\App.exe` }, func(netip.AddrPort) bool { return false })
	p.poll()
	p.poll()
	if lists != 2 || names != 1 {
		t.Fatalf("lists=%d names=%d (one process name lookup per new connection)", lists, names)
	}
	if len(p.prev) != 1 {
		t.Fatalf("only the outgoing established row counts: %v", p.prev)
	}
}

func TestSeenTTL(t *testing.T) {
	var s seen
	d := netip.MustParseAddrPort("203.0.113.9:443")
	if s.has(d) {
		t.Fatal("empty")
	}
	s.mark(d)
	if !s.has(d) {
		t.Fatal("marked")
	}
	s.mu.Lock()
	s.m[d] = time.Now().Add(-2 * seenTTL)
	s.mu.Unlock()
	if s.has(d) {
		t.Fatal("expired")
	}
}
