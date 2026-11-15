package windefense

import (
	"context"
	"encoding/binary"
	"net/netip"
	"sync"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/defense"
)

// TCP states of the Windows connection table (MIB_TCP_STATE).
const (
	tcpListen      = 2
	tcpSynSent     = 3
	tcpEstablished = 5
)

// connPoll is how often the connection table is read.
const connPoll = 10 * time.Second

// seenTTL: a destination the netstack reported lately is not counted a
// second time as a fresh connection by the table poll.
const seenTTL = 30 * time.Second

// TCPConn is one row of the system's TCP table.
type TCPConn struct {
	State  int
	Local  netip.AddrPort
	Remote netip.AddrPort
	PID    uint32
}

// ParseTCP4 reads a MIB_TCPTABLE_OWNER_PID (GetExtendedTcpTable, AF_INET,
// TCP_TABLE_OWNER_PID_ALL): a count, then rows of six 32-bit words (state,
// local address, local port, remote address, remote port, pid). Ports sit
// in the low 16 bits in network order. Little-endian, like every Windows
// target. Short or inconsistent buffers give what is whole.
func ParseTCP4(b []byte) []TCPConn {
	const row = 24
	n := tableCount(b, row)
	out := make([]TCPConn, 0, n)
	for i := 0; i < n; i++ {
		r := b[4+i*row : 4+(i+1)*row]
		out = append(out, TCPConn{
			State:  int(binary.LittleEndian.Uint32(r[0:])),
			Local:  netip.AddrPortFrom(netip.AddrFrom4([4]byte(r[4:8])), binary.BigEndian.Uint16(r[8:10])),
			Remote: netip.AddrPortFrom(netip.AddrFrom4([4]byte(r[12:16])), binary.BigEndian.Uint16(r[16:18])),
			PID:    binary.LittleEndian.Uint32(r[20:]),
		})
	}
	return out
}

// ParseTCP6 reads a MIB_TCP6TABLE_OWNER_PID (AF_INET6): rows of local
// address (16), scope id, port, remote address (16), scope id, port, state,
// pid: 56 bytes.
func ParseTCP6(b []byte) []TCPConn {
	const row = 56
	n := tableCount(b, row)
	out := make([]TCPConn, 0, n)
	for i := 0; i < n; i++ {
		r := b[4+i*row : 4+(i+1)*row]
		out = append(out, TCPConn{
			State:  int(binary.LittleEndian.Uint32(r[48:])),
			Local:  netip.AddrPortFrom(netip.AddrFrom16([16]byte(r[0:16])), binary.BigEndian.Uint16(r[20:22])),
			Remote: netip.AddrPortFrom(netip.AddrFrom16([16]byte(r[24:40])), binary.BigEndian.Uint16(r[44:46])),
			PID:    binary.LittleEndian.Uint32(r[52:]),
		})
	}
	return out
}

func tableCount(b []byte, row int) int {
	if len(b) < 4 {
		return 0
	}
	n := int(binary.LittleEndian.Uint32(b))
	if max := (len(b) - 4) / row; n > max {
		n = max
	}
	return n
}

// connPoller turns successive table snapshots into NoteConn calls: the
// outgoing connections that are new since the last snapshot, with the
// program's file name.
type connPoller struct {
	m        *defense.Manager
	list     func() ([]TCPConn, error)
	procName func(pid uint32) string // path or name of the process, "" = unknown
	recent   func(dst netip.AddrPort) bool

	prev  map[string]bool
	first bool
}

func newConnPoller(m *defense.Manager, list func() ([]TCPConn, error), name func(uint32) string, recent func(netip.AddrPort) bool) *connPoller {
	return &connPoller{m: m, list: list, procName: name, recent: recent, prev: map[string]bool{}, first: true}
}

// poll reads the table once. Connections that already existed at the first
// read count for first contact only (fresh=false), as on Linux; so do the
// ones the netstack just reported (no double beacon count).
func (p *connPoller) poll() {
	if !(p.m.Watching(defense.FeatBeacon) || p.m.Watching(defense.FeatFirstSeen)) {
		p.prev, p.first = map[string]bool{}, true
		return
	}
	rows, err := p.list()
	if err != nil {
		return
	}
	listen := map[uint16]bool{}
	for _, c := range rows {
		if c.State == tcpListen {
			listen[c.Local.Port()] = true
		}
	}
	names := map[uint32]string{}
	cur := make(map[string]bool, len(rows))
	for _, c := range rows {
		if c.State != tcpEstablished && c.State != tcpSynSent {
			continue
		}
		dst := netip.AddrPortFrom(c.Remote.Addr().Unmap(), c.Remote.Port())
		if !dst.IsValid() || dst.Port() == 0 || listen[c.Local.Port()] {
			continue
		}
		key := c.Local.String() + ">" + dst.String() + "/" + itoa(c.PID)
		cur[key] = true
		if p.prev[key] {
			continue
		}
		app, ok := names[c.PID]
		if !ok {
			app = ""
			if c.PID > 4 && p.procName != nil {
				app = p.procName(c.PID)
			}
			names[c.PID] = app
		}
		if app != "" {
			app = baseName(app)
		}
		fresh := !p.first && !(p.recent != nil && p.recent(dst))
		p.m.NoteConn(app, dst, fresh)
	}
	p.prev, p.first = cur, false
}

func itoa(n uint32) string {
	var b [10]byte
	i := len(b)
	for {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
		if n == 0 {
			break
		}
	}
	return string(b[i:])
}

// seen remembers destinations the netstack reported (see seenTTL).
type seen struct {
	mu sync.Mutex
	m  map[netip.AddrPort]time.Time
}

func (s *seen) mark(dst netip.AddrPort) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil || len(s.m) > 4000 {
		s.m = map[netip.AddrPort]time.Time{}
	}
	s.m[dst] = time.Now()
}

func (s *seen) has(dst netip.AddrPort) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.m[dst]
	return ok && time.Since(t) < seenTTL
}

// connLoop runs the poller until ctx ends. It does nothing where the
// platform has no table (listConns nil).
func (r *Runner) connLoop(ctx context.Context) {
	if listConns == nil {
		return
	}
	p := newConnPoller(r.M, listConns, processName, r.seen.has)
	tk := time.NewTicker(connPoll)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			p.poll()
		}
	}
}
