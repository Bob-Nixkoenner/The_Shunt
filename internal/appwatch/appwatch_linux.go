package appwatch

import (
	"encoding/binary"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
)

// Watcher watches process starts and applies Targets.
type Watcher struct {
	Log   *slog.Logger
	Mover Mover
	Proc  string // /proc
	// Skip is the cgroup prefix (relative path) of processes that must not
	// be touched: shuntd itself and everything already placed by Shunt.
	Skip string

	// Recheck is a cgroup prefix inside Skip whose processes are still
	// looked at: the app firewall's waiting groups (a held wrapper script
	// that execs the real program must not decide for it).
	Recheck string
	// Unknown, if set, gets every process no target matched (and that
	// is not already placed by Shunt): the app firewall decides on it.
	Unknown func(pid int, p Proc)

	mu      sync.RWMutex
	fast    bool // app firewall on: rescan often, a missed start would leave unasked
	targets []Target
	seen    map[int]string // pid -> comm when last checked (exec changes it)
	placed  map[int]placement
}

// SetRecheck sets the cgroup prefix inside Skip that is looked at anyway
// (the app firewall's waiting groups; see Recheck).
func (w *Watcher) SetRecheck(prefix string) {
	w.mu.Lock()
	w.Recheck = prefix
	w.mu.Unlock()
}

// SetFast makes the safety-net scan run every 250ms instead of every 5s. The
// daemon turns it on while the app firewall holds programs (ask/block): a
// start the process connector missed must be held within a moment, not after
// seconds (by then it has already used the default route).
func (w *Watcher) SetFast(on bool) {
	w.mu.Lock()
	w.fast = on
	w.mu.Unlock()
}

func (w *Watcher) interval(connector bool) time.Duration {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if !connector || w.fast {
		return scanFast
	}
	return scanSlow
}

// SetTargets replaces the rules and re-scans running processes.
func (w *Watcher) SetTargets(t []Target, skip string) {
	w.mu.Lock()
	w.targets, w.Skip = t, skip
	w.seen = map[int]string{}
	w.mu.Unlock()
	w.scan()
}

// Run blocks, handling exec events until stop is closed.
func (w *Watcher) Run(stop <-chan struct{}) {
	events, lost, err := listenExec()
	if err != nil {
		w.Log.Info("process connector unavailable, scanning /proc instead", "err", err)
	} else {
		go func() {
			for pid := range events {
				w.check(pid)
			}
		}()
	}
	go w.sticky(stop)
	t := time.NewTimer(w.interval(err == nil))
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-lost: // events dropped (ENOBUFS / channel full): look right now
			w.scan()
		case <-t.C:
			w.scan()
			t.Reset(w.interval(err == nil))
		}
	}
}

func (w *Watcher) scan() {
	ents, err := os.ReadDir(w.proc())
	if err != nil {
		return
	}
	alive := map[int]bool{}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		alive[pid] = true
		w.mu.RLock()
		seen, ok := w.seen[pid]
		w.mu.RUnlock()
		// a known pid is checked again when its name changed: it exec'd
		// another program (the process connector may have missed it)
		if !ok || seen != comm(w.proc(), pid) {
			w.check(pid)
		}
	}
	w.mu.Lock()
	for pid := range w.seen {
		if !alive[pid] {
			delete(w.seen, pid)
		}
	}
	w.mu.Unlock()
}

func (w *Watcher) proc() string {
	if w.Proc == "" {
		return "/proc"
	}
	return w.Proc
}

// check looks at one process and moves it if a target matches.
func (w *Watcher) check(pid int) {
	w.mu.Lock()
	if w.seen == nil {
		w.seen = map[int]string{}
	}
	w.seen[pid] = comm(w.proc(), pid)
	targets, skip, unknown, recheck := w.targets, w.Skip, w.Unknown, w.Recheck
	w.mu.Unlock()
	if (len(targets) == 0 && unknown == nil) || pid <= 1 {
		return
	}
	info, err := readProc(w.proc(), pid)
	if err != nil || info.argv0 == "" { // gone, or a kernel thread (empty cmdline)
		return
	}
	held := recheck != "" && strings.HasPrefix(info.cgroup, recheck+"/")
	if skip != "" && (info.cgroup == skip || strings.HasPrefix(info.cgroup, skip+"/")) && !held {
		return // shuntd itself, or already placed (shunt run wins)
	}
	for _, t := range targets {
		if t.Path == info.cgroup {
			return
		}
		if matchAny(t.Sels, info) && matchArgs(t.Args, w.proc(), pid) {
			if err := w.Mover.Move(t.Path, pid); err != nil {
				if !errors.Is(err, unix.ESRCH) {
					w.Log.Warn("cannot move app", "pid", pid, "app", info.comm, "rule", t.Name, "err", err)
				}
				return
			}
			w.Log.Info("app attached", "pid", pid, "app", info.comm, "rule", t.Name)
			w.Place(pid, t.Path)
			return
		}
	}
	if unknown != nil {
		unknown(pid, Proc{Comm: info.comm, Exe: info.exe, Argv0: info.argv0, Cgroup: info.cgroup, TTY: info.tty, UID: info.uid})
	}
}

func comm(proc string, pid int) string {
	b, _ := os.ReadFile(filepath.Join(proc, strconv.Itoa(pid), "comm"))
	return strings.TrimSpace(string(b))
}

type procInfo struct {
	comm   string
	exe    string // empty if unreadable (other user's process, see readProc)
	argv0  string
	cgroup string // v2 path without leading slash
	tty    bool
	uid    int
}

func readProc(proc string, pid int) (procInfo, error) {
	dir := filepath.Join(proc, strconv.Itoa(pid))
	var p procInfo
	b, err := os.ReadFile(filepath.Join(dir, "comm"))
	if err != nil {
		return p, err
	}
	p.comm = strings.TrimSpace(string(b))
	if b, err := os.ReadFile(filepath.Join(dir, "cmdline")); err == nil {
		p.argv0, _, _ = strings.Cut(string(b), "\x00")
	}
	// Reading /proc/<pid>/exe of another user's process needs CAP_SYS_PTRACE,
	// which shuntd deliberately does not have (a compromised daemon could
	// inject into any process). Without it, fall back to an absolute argv[0].
	// argv[0] can be chosen by the program itself, so it only helps a
	// program route itself, which it could do anyway.
	p.exe, _ = os.Readlink(filepath.Join(dir, "exe"))
	p.exe = strings.TrimSuffix(p.exe, " (deleted)")
	if p.exe == "" && strings.HasPrefix(p.argv0, "/") {
		p.exe = p.argv0
	}
	// field 7 of stat: controlling terminal (0 = none)
	if b, err := os.ReadFile(filepath.Join(dir, "stat")); err == nil {
		if i := strings.LastIndexByte(string(b), ')'); i >= 0 {
			if f := strings.Fields(string(b)[i+1:]); len(f) > 4 {
				p.tty = f[4] != "0"
			}
		}
	}
	if st, err := os.Stat(dir); err == nil {
		if s, ok := st.Sys().(*syscall.Stat_t); ok {
			p.uid = int(s.Uid)
		}
	}
	b, err = os.ReadFile(filepath.Join(dir, "cgroup"))
	if err != nil {
		return p, err
	}
	for _, l := range strings.Split(string(b), "\n") {
		if c, ok := strings.CutPrefix(l, "0::"); ok {
			p.cgroup = strings.Trim(c, "/")
		}
	}
	return p, nil
}

func matchAny(sels []config.AppSel, p procInfo) bool {
	for _, s := range sels {
		switch s.Kind {
		case "exe":
			if p.exe == s.Value {
				return true
			}
		case "name":
			// comm is truncated to 15 bytes by the kernel
			n := s.Value
			if len(n) > 15 {
				n = n[:15]
			}
			if p.comm == n || (p.exe != "" && filepath.Base(p.exe) == s.Value) || filepath.Base(p.argv0) == s.Value {
				return true
			}
		case "flatpak":
			// flatpak run puts the sandbox into app-flatpak-<id>-<n>.scope
			if strings.Contains(p.cgroup, "app-flatpak-"+s.Value+"-") {
				return true
			}
		}
	}
	return false
}

// matchArgs checks the command line (arguments joined by spaces).
func matchArgs(args []string, proc string, pid int) bool {
	if len(args) == 0 {
		return true
	}
	b, err := os.ReadFile(filepath.Join(proc, strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return false
	}
	cmd := " " + strings.ReplaceAll(strings.TrimRight(string(b), "\x00"), "\x00", " ") + " "
	for _, a := range args {
		if strings.Contains(cmd, " "+a+" ") {
			return true
		}
	}
	return false
}

// --- process connector -------------------------------------------------

const (
	cnIdxProc         = 1
	cnValProc         = 1
	procCnMcastListen = 1
	procEventExec     = 0x00000002
	nlmsgHdrLen       = 16
	cnMsgLen          = 20
)

const (
	scanFast = 250 * time.Millisecond // no connector, or app firewall on
	scanSlow = 5 * time.Second
)

// listenExec subscribes to exec events; the first channel yields tgids. The
// second one gets a signal whenever events may have been lost (ENOBUFS, or
// the first channel was full): the caller scans /proc at once.
func listenExec() (<-chan int, <-chan struct{}, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.NETLINK_CONNECTOR)
	if err != nil {
		return nil, nil, err
	}
	sa := &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: cnIdxProc, Pid: uint32(os.Getpid())}
	if err := unix.Bind(fd, sa); err != nil {
		unix.Close(fd)
		return nil, nil, err
	}
	// netlink header + cn_msg + op
	msg := make([]byte, nlmsgHdrLen+cnMsgLen+4)
	ne := binary.NativeEndian
	ne.PutUint32(msg[0:], uint32(len(msg)))
	ne.PutUint16(msg[4:], unix.NLMSG_DONE)
	ne.PutUint32(msg[12:], uint32(os.Getpid()))
	ne.PutUint32(msg[16:], cnIdxProc)
	ne.PutUint32(msg[20:], cnValProc)
	ne.PutUint16(msg[32:], 4)
	ne.PutUint32(msg[36:], procCnMcastListen)
	if err := unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		unix.Close(fd)
		return nil, nil, err
	}
	ch := make(chan int, 256)
	lost := make(chan struct{}, 1)
	signalLost := func() {
		select {
		case lost <- struct{}{}:
		default: // a scan is already pending
		}
	}
	go func() {
		defer unix.Close(fd)
		buf := make([]byte, 8192)
		for {
			n, _, err := unix.Recvfrom(fd, buf, 0)
			if err != nil {
				if errors.Is(err, unix.ENOBUFS) {
					signalLost() // events lost: scan now, not at the next tick
					continue
				}
				if errors.Is(err, unix.EINTR) {
					continue
				}
				close(ch)
				return
			}
			for _, pid := range parseExecEvents(buf[:n]) {
				select {
				case ch <- pid:
				default: // full: scan right away
					signalLost()
				}
			}
		}
	}()
	return ch, lost, nil
}

// parseExecEvents extracts the tgids of exec events from a netlink datagram.
func parseExecEvents(b []byte) []int {
	ne := binary.NativeEndian
	var out []int
	for len(b) >= nlmsgHdrLen {
		l := int(ne.Uint32(b[0:]))
		if l < nlmsgHdrLen || l > len(b) {
			break
		}
		m := b[nlmsgHdrLen:l]
		// cn_msg header, then struct proc_event {what, cpu, timestamp, data}
		if len(m) >= cnMsgLen+16+8 && ne.Uint32(m[0:]) == cnIdxProc {
			ev := m[cnMsgLen:]
			if ne.Uint32(ev[0:]) == procEventExec {
				out = append(out, int(ne.Uint32(ev[16+4:]))) // exec: pid, tgid
			}
		}
		next := (l + 3) &^ 3 // messages are 4-byte aligned
		if next > len(b) {
			break
		}
		b = b[next:]
	}
	return out
}
