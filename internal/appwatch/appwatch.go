// Package appwatch puts programs into their route's cgroup as soon as they
// start, so app rules work without `shunt run`.
//
// Exec events come from the kernel's process connector (netlink). It only
// exists in the initial network namespace; elsewhere (tests, containers) a
// /proc scan every 250ms takes over. A slow rescan also runs alongside the
// connector because netlink can drop events under load.
//
// This is best effort by nature: a program could open a socket in the short
// window between exec and the move; that socket keeps its old route. For
// a race-free start use `shunt run` or a menu entry made by `shunt desktop`.
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
	"time"

	"golang.org/x/sys/unix"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
)

// Target is an app rule: processes matching Sels go into cgroup Path.
type Target struct {
	Name string
	Sels []config.AppSel
	Args []string // command line must contain one of these (if any)
	Path string   // cgroup path relative to the mount
}

// Mover moves a process into a cgroup.
type Mover interface {
	Move(rel string, pid int) error
}

// Watcher watches process starts and applies Targets.
type Watcher struct {
	Log   *slog.Logger
	Mover Mover
	Proc  string // /proc
	// Skip is the cgroup prefix (relative path) of processes that must not
	// be touched: shuntd itself and everything already placed by Shunt.
	Skip string

	mu      sync.RWMutex
	targets []Target
	seen    map[int]bool
}

// SetTargets replaces the rules and re-scans running processes.
func (w *Watcher) SetTargets(t []Target, skip string) {
	w.mu.Lock()
	w.targets, w.Skip = t, skip
	w.seen = map[int]bool{}
	w.mu.Unlock()
	w.scan()
}

// Run blocks, handling exec events until stop is closed.
func (w *Watcher) Run(stop <-chan struct{}) {
	events, err := listenExec()
	interval := 5 * time.Second
	if err != nil {
		w.Log.Info("process connector unavailable, scanning /proc instead", "err", err)
		interval = 250 * time.Millisecond
	} else {
		go func() {
			for pid := range events {
				w.check(pid)
			}
		}()
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			w.scan()
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
		seen := w.seen[pid]
		w.mu.RUnlock()
		if !seen {
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
		w.seen = map[int]bool{}
	}
	w.seen[pid] = true
	targets, skip := w.targets, w.Skip
	w.mu.Unlock()
	if len(targets) == 0 || pid <= 1 {
		return
	}
	info, err := readProc(w.proc(), pid)
	if err != nil || info.argv0 == "" { // gone, or a kernel thread (empty cmdline)
		return
	}
	if skip != "" && (info.cgroup == skip || strings.HasPrefix(info.cgroup, skip+"/")) {
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
			return
		}
	}
}

type procInfo struct {
	comm   string
	exe    string // empty if unreadable (other user's process, see readProc)
	argv0  string
	cgroup string // v2 path without leading slash
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

// listenExec subscribes to exec events; the channel yields tgids.
func listenExec() (<-chan int, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.NETLINK_CONNECTOR)
	if err != nil {
		return nil, err
	}
	sa := &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: cnIdxProc, Pid: uint32(os.Getpid())}
	if err := unix.Bind(fd, sa); err != nil {
		unix.Close(fd)
		return nil, err
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
		return nil, err
	}
	ch := make(chan int, 256)
	go func() {
		defer unix.Close(fd)
		buf := make([]byte, 8192)
		for {
			n, _, err := unix.Recvfrom(fd, buf, 0)
			if err != nil {
				if errors.Is(err, unix.EINTR) || errors.Is(err, unix.ENOBUFS) {
					continue // ENOBUFS: events lost, the periodic scan catches up
				}
				close(ch)
				return
			}
			for _, pid := range parseExecEvents(buf[:n]) {
				select {
				case ch <- pid:
				default: // full: the scan will find it
				}
			}
		}
	}()
	return ch, nil
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
