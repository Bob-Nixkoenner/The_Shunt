//go:build windows

package defense

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Sensors runs the checks that work on Windows without a packet driver:
// the gateway watch (ARP/NDP table, NotifyIpNetTable plus a poll every few
// seconds) and the evil-twin check (same Wi-Fi name, new gateway MAC). No
// DHCP, router advertisement or DNS comparison here. Findings never contain
// SSIDs or MACs.
type Sensors struct {
	M     *Manager
	Log   *slog.Logger
	DNS   DNSCheck // unused on Windows
	Twins *TwinStore
	Mark  uint32 // unused on Windows

	mu     sync.Mutex
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// ProbeSoon does nothing: there is no DHCP probe on Windows.
func (s *Sensors) ProbeSoon() {}

// neighbourPoll is how often the table is compared even without a signal.
const neighbourPoll = 5 * time.Second

// SetEnv (re)starts the sensors for the network now in use.
func (s *Sensors) SetEnv(env Env) {
	s.Stop()
	if env.Iface == "" {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.mu.Lock()
	s.cancel = cancel
	s.mu.Unlock()
	run := func(f func()) {
		s.wg.Add(1)
		go func() { defer s.wg.Done(); GuardLoop(ctx, s.log(), "sensor", f) }()
	}
	if s.Twins != nil && s.Twins.Check(env.SSID, env.GatewayMAC) {
		s.emit(FeatEvilTwin, TwinEvent())
	}
	run(func() { s.neighbours(ctx, env) })
}

// Stop ends all sensors and waits for them.
func (s *Sensors) Stop() {
	s.mu.Lock()
	c := s.cancel
	s.cancel = nil
	s.mu.Unlock()
	if c != nil {
		c()
	}
	s.wg.Wait()
}

func (s *Sensors) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func (s *Sensors) emit(feat string, ev Event) {
	if s.M != nil && s.M.Watching(feat) {
		s.M.Report(ev)
	}
}

// MIB_IPNET_ROW2 (netioapi.h), 88 bytes on 32 and 64 bit alike.
type ipNetRow2 struct {
	Address  [28]byte // SOCKADDR_INET
	IfIndex  uint32
	Luid     uint64
	PhysAddr [32]byte
	PhysLen  uint32
	State    int32
	Flags    uint8
	_        [3]byte
	Reach    uint32
}

var _ [88]byte = [unsafe.Sizeof(ipNetRow2{})]byte{}

var (
	modIphlp        = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetNetTable = modIphlp.NewProc("GetIpNetTable2")
	procFreeMib     = modIphlp.NewProc("FreeMibTable")
	procNotifyNet   = modIphlp.NewProc("NotifyIpNetTable")
	procCancelNote  = modIphlp.NewProc("CancelMibChangeNotify2")

	cbOnce sync.Once
	cbPtr  uintptr
	cbMu   sync.Mutex
	cbSubs = map[chan struct{}]struct{}{}
)

// netCallback runs on a Windows thread whenever the table changes; it only
// wakes the readers.
func netCallback(ctx, row, typ uintptr) uintptr {
	cbMu.Lock()
	for c := range cbSubs {
		select {
		case c <- struct{}{}:
		default:
		}
	}
	cbMu.Unlock()
	return 0
}

// subscribe returns a channel that gets a signal on table changes and a
// function that ends it. When NotifyIpNetTable fails the channel stays
// silent and the poll alone works.
func subscribe() (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	cbOnce.Do(func() { cbPtr = syscall.NewCallback(netCallback) })
	cbMu.Lock()
	cbSubs[ch] = struct{}{}
	cbMu.Unlock()
	var h windows.Handle
	// iphlpapi.dll has no change notification for the neighbour table on every
	// Windows (found in a Windows 11 VM: a missing function makes Call panic):
	// look it up first, else the poll alone does the work
	r := uintptr(1)
	if procNotifyNet.Find() == nil {
		r, _, _ = procNotifyNet.Call(uintptr(windows.AF_UNSPEC), cbPtr, 0, 0, uintptr(unsafe.Pointer(&h)))
	}
	return ch, func() {
		if r == 0 && h != 0 {
			procCancelNote.Call(uintptr(h))
		}
		cbMu.Lock()
		delete(cbSubs, ch)
		cbMu.Unlock()
	}
}

// readTable calls f for every neighbour row of the interface with index idx.
func readTable(idx uint32, f func(ip netip.Addr, mac []byte, state int)) error {
	var tab uintptr
	if r, _, _ := procGetNetTable.Call(uintptr(windows.AF_UNSPEC), uintptr(unsafe.Pointer(&tab))); r != 0 {
		return windows.Errno(r)
	}
	defer procFreeMib.Call(tab)
	p := *(*unsafe.Pointer)(unsafe.Pointer(&tab))
	count := *(*uint32)(p)
	rows := unsafe.Slice((*ipNetRow2)(unsafe.Add(p, 8)), int(count))
	for i := range rows {
		r := &rows[i]
		if r.IfIndex != idx {
			continue
		}
		var ip netip.Addr
		switch *(*uint16)(unsafe.Pointer(&r.Address[0])) {
		case windows.AF_INET:
			ip = netip.AddrFrom4([4]byte(r.Address[4:8]))
		case windows.AF_INET6:
			ip = netip.AddrFrom16([16]byte(r.Address[8:24]))
		}
		l := int(r.PhysLen)
		if l > len(r.PhysAddr) {
			l = len(r.PhysAddr)
		}
		f(ip, r.PhysAddr[:l], int(r.State))
	}
	return nil
}

func (s *Sensors) neighbours(ctx context.Context, env Env) {
	if env.GatewayIP == "" {
		return
	}
	ifc, err := net.InterfaceByName(env.Iface)
	if err != nil {
		return
	}
	idx := uint32(ifc.Index)
	gw := newGWWatch(env.GatewayIP, env.GatewayMAC)
	poll := func() {
		err := readTable(idx, func(ip netip.Addr, mac []byte, state int) {
			if a, m, ok := neighEntry(ip, mac, state); ok {
				if ev, hit := gw.Feed(a, m); hit {
					s.emit(FeatARP, ev)
				}
			}
		})
		if err != nil {
			s.log().Debug("defense: neighbour table", "err", err)
		}
	}
	ch, stop := subscribe()
	defer stop()
	poll()
	tick := time.NewTicker(neighbourPoll)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			poll()
		case <-ch:
			poll()
		}
	}
}
