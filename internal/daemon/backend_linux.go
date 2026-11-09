package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"github.com/Bob-Nixkoenner/the_shunt/internal/appwatch"
	"github.com/Bob-Nixkoenner/the_shunt/internal/cgroup"
	"github.com/Bob-Nixkoenner/the_shunt/internal/dnsproxy"
	"github.com/Bob-Nixkoenner/the_shunt/internal/engine"
	"github.com/Bob-Nixkoenner/the_shunt/internal/firewall"
	"github.com/Bob-Nixkoenner/the_shunt/internal/nft"
	"github.com/Bob-Nixkoenner/the_shunt/internal/racebpf"
	"github.com/Bob-Nixkoenner/the_shunt/internal/routing"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// DefaultBackend is the platform's backend.
func DefaultBackend() Backend { return &linuxBackend{} }

// linuxBackend: cgroup v2 groups, nftables marks and rules, policy routing
// tables (see packages cgroup, nft, routing, appwatch, racebpf).
type linuxBackend struct {
	cg    cgroup.Manager
	mu    sync.Mutex // start (the watcher's goroutines read it)
	start *racebpf.Guard
	// startErr: loading the eBPF program failed once; not retried
	startErr error
}

func (b *linuxBackend) Init() (string, error) {
	mount, err := cgroup.Mount()
	if err != nil {
		return "", err
	}
	b.cg = cgroup.Manager{Mount: mount}
	return cgroup.Self()
}

func (b *linuxBackend) Groups() firewall.CGroups { return b.cg }

func (b *linuxBackend) Render(p *engine.Plan) (string, error) { return nft.Render(p) }

func (b *linuxBackend) Emergency(g engine.Group, dst []netip.Prefix) (string, error) {
	return nft.RenderEmergency(g, dst)
}

func (b *linuxBackend) EmergencyOff() string { return nft.DeleteScript(nft.EmergencyTable) }

func (b *linuxBackend) EmergencyIntact() bool {
	out, err := exec.Command("nft", "list", "tables").Output()
	if err != nil {
		return true
	}
	return strings.Contains("\n"+string(out), "\ntable inet "+nft.EmergencyTable+"\n")
}

func (b *linuxBackend) Apply(ruleset string, held map[string]engine.Group) error {
	ask, err := nft.AskRules(held)
	if err != nil {
		return err
	}
	return nft.Apply(ruleset + ask)
}

func (b *linuxBackend) Hold(held map[string]engine.Group) error {
	s, err := nft.AskRules(held)
	if err != nil {
		return err
	}
	return nft.Apply(s)
}

func (b *linuxBackend) WatchHeld(ctx context.Context, seen func(id string, uid int)) error {
	return firewall.Listen(ctx, seen)
}

func (b *linuxBackend) SyncRoutes(p *engine.Plan, up map[string]bool) error {
	return routing.Sync(p, up)
}

func (b *linuxBackend) Panic(on bool) error {
	if on {
		return nft.Apply(nft.RenderPanic())
	}
	return nft.Apply(nft.DeleteScript(nft.PanicTable))
}

// tcpMark matches conntrack entries of TCP flows with one ct mark.
type tcpMark uint32

func (m tcpMark) MatchConntrackFlow(f *netlink.ConntrackFlow) bool {
	return f.Forward.Protocol == unix.IPPROTO_TCP && f.Mark == uint32(m)
}

func (b *linuxBackend) ForgetTCP(mark uint32) (int, error) {
	n := 0
	var errs []error
	for _, fam := range []netlink.InetFamily{unix.AF_INET, unix.AF_INET6} {
		k, err := netlink.ConntrackDeleteFilters(netlink.ConntrackTable, fam, tcpMark(mark))
		n += int(k)
		errs = append(errs, err)
	}
	return n, errors.Join(errs...)
}

// strayFlow matches flows started by this machine (source is a local
// address) whose destination is neither loopback nor in keep.
type strayFlow struct {
	local map[netip.Addr]bool
	keep  []netip.Prefix
}

func (m strayFlow) MatchConntrackFlow(f *netlink.ConntrackFlow) bool {
	if f.Forward.Protocol != unix.IPPROTO_TCP && f.Forward.Protocol != unix.IPPROTO_UDP {
		return false
	}
	src, ok1 := netip.AddrFromSlice(f.Forward.SrcIP)
	dst, ok2 := netip.AddrFromSlice(f.Forward.DstIP)
	if !ok1 || !ok2 {
		return false
	}
	src, dst = src.Unmap(), dst.Unmap()
	if !m.local[src] || dst.IsLoopback() {
		return false
	}
	for _, p := range m.keep {
		if p.Contains(dst) {
			return false
		}
	}
	return true
}

// ForgetStray: see EmergencyForgetter.
func (b *linuxBackend) ForgetStray(keep []netip.Prefix) (int, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return 0, err
	}
	m := strayFlow{local: map[netip.Addr]bool{}, keep: keep}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if ad, ok := netip.AddrFromSlice(ipn.IP); ok {
				m.local[ad.Unmap()] = true
			}
		}
	}
	n := 0
	var errs []error
	for _, fam := range []netlink.InetFamily{unix.AF_INET, unix.AF_INET6} {
		k, err := netlink.ConntrackDeleteFilters(netlink.ConntrackTable, fam, m)
		n += int(k)
		errs = append(errs, err)
	}
	return n, errors.Join(errs...)
}

func (b *linuxBackend) Stopped(p *engine.Plan) error {
	s, err := nft.StoppedDNS(p)
	if err != nil || s == "" {
		return err
	}
	return nft.Apply(s)
}

// Intact: table inet shunt is still loaded. `nft list tables` is cheap (no
// rules are read); a failing nft counts as intact (nothing proven).
func (b *linuxBackend) Intact() bool {
	out, err := exec.Command("nft", "list", "tables").Output()
	if err != nil {
		return true
	}
	return strings.Contains("\n"+string(out), "\ntable inet "+nft.Table+"\n")
}

func (b *linuxBackend) LiftLockdown() error {
	return nft.Apply(nft.DeleteScript(nft.LockdownTable))
}

func (b *linuxBackend) Cleanup() error {
	var errs []error
	for _, t := range []string{nft.Table, nft.PanicTable, nft.LockdownTable, nft.EmergencyTable} {
		errs = append(errs, nft.Apply(nft.DeleteScript(t)))
	}
	errs = append(errs, nft.Apply(nft.DeleteArpScript()))
	errs = append(errs, routing.Cleanup())
	return errors.Join(errs...)
}

func (b *linuxBackend) DomainSets() dnsproxy.SetWriter { return dnsproxy.NftSets{Table: nft.Table} }

func (b *linuxBackend) Watcher(log *slog.Logger, unknown func(int, appwatch.Proc)) AppWatcher {
	return &appwatch.Watcher{Log: log, Mover: b.cg, Unknown: unknown, Decided: b.release, Now: racebpf.Now}
}

func (b *linuxBackend) CgroupOf(pid int) (string, bool) {
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cgroup")
	if err != nil {
		return "", false
	}
	for _, l := range strings.Split(string(raw), "\n") {
		if c, ok := strings.CutPrefix(l, "0::"); ok {
			return strings.Trim(c, "/"), true
		}
	}
	return "", false
}

func (b *linuxBackend) Comm(pid int) (string, bool) {
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm")
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(raw)), true
}

func (b *linuxBackend) Pids() []int {
	ents, _ := os.ReadDir("/proc")
	var out []int
	for _, e := range ents {
		if pid, err := strconv.Atoi(e.Name()); err == nil {
			out = append(out, pid)
		}
	}
	return out
}

func (b *linuxBackend) StartGuard(root string, entries map[string]engine.StartEntry) error {
	if b.startErr != nil {
		return b.startErr
	}
	if b.start == nil {
		if len(entries) == 0 {
			return nil // load it only once an app rule needs it
		}
		g, err := racebpf.Start(b.cg.Mount, root)
		if err != nil {
			b.startErr = err
			return err
		}
		b.mu.Lock()
		b.start = g
		b.mu.Unlock()
	}
	m := make(map[string]racebpf.Entry, len(entries))
	for n, e := range entries {
		m[n] = racebpf.Entry{Mark: e.Mark, Hold: e.Hold}
	}
	if err := b.start.SetEntries(m); err != nil {
		return err
	}
	if b.start.Partial != nil {
		return fmt.Errorf("only by program name, no threads, children or holds: %w", b.start.Partial)
	}
	return nil
}

func (b *linuxBackend) StartGuardStats() map[string]uint64 {
	b.mu.Lock()
	g := b.start
	b.mu.Unlock()
	if g == nil {
		return nil
	}
	s := g.Stats()
	m := map[string]uint64{"marked": s[racebpf.StatMarked], "held": s[racebpf.StatHeld],
		"expired": s[racebpf.StatExpired], "marked_by_name": s[racebpf.StatComm]}
	if g.Raw {
		m["raw_tracepoints"] = 1 // kernel refused perf events (Debian: perf_event_paranoid=3)
	}
	if g.Limited != "" {
		m["no_child_inherit"] = 1 // children of a rule's program are not followed
	}
	return m
}

// release ends a held program's wait once the watcher decided on it.
func (b *linuxBackend) release(pid int, since int64) {
	b.mu.Lock()
	g := b.start
	b.mu.Unlock()
	if g != nil {
		g.Release(pid, since)
	}
}
