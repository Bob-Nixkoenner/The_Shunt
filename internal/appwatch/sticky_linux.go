package appwatch

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Sticky routes.
//
// Desktops move freshly started programs into systemd scopes of their own
// (COSMIC: app-cosmic-<app>-<n>.scope), and Chromium-based browsers move
// themselves once more (app-org.chromium.Chromium-<n>.scope). Both take
// the process out of the Shunt group it was started in, and with it out of
// its route. So every process Shunt placed is remembered with its group;
// a fast loop puts it back when it left, and adopts its children (which
// the browser may already have started in the new scope).

type placement struct {
	path  string
	start string // /proc/<pid>/stat field 22: guards against pid reuse
}

// StickyInterval is how often placed processes are checked. Sockets opened
// while a process is outside its group keep the wrong route, so this is
// short; it only reads a few /proc files per placed process.
var StickyInterval = 100 * time.Millisecond

// Place remembers that pid belongs into the cgroup path (relative).
func (w *Watcher) Place(pid int, path string) {
	start := startTime(w.proc(), pid)
	if start == "" {
		return
	}
	w.mu.Lock()
	if w.placed == nil {
		w.placed = map[int]placement{}
	}
	w.placed[pid] = placement{path: path, start: start}
	w.mu.Unlock()
}

// keepPlaced runs one round: moves placed processes back into their group
// and places their children.
func (w *Watcher) keepPlaced() {
	w.mu.RLock()
	if len(w.placed) == 0 {
		w.mu.RUnlock()
		return
	}
	snap := make(map[int]placement, len(w.placed))
	for pid, p := range w.placed {
		snap[pid] = p
	}
	w.mu.RUnlock()

	proc := w.proc()
	w.mu.RLock()
	skip := w.Skip
	w.mu.RUnlock()
	// outside: not in Shunt's tree at all (moved by systemd/the desktop).
	// A move into another Shunt group was Shunt's own doing and stays.
	outside := func(cg string) bool {
		return cg != "" && (skip == "" || (cg != skip && !strings.HasPrefix(cg, skip+"/")))
	}
	var dead []int
	for pid, p := range snap {
		if startTime(proc, pid) != p.start {
			dead = append(dead, pid)
			continue
		}
		if cg := cgroupOf(proc, pid); outside(cg) {
			if err := w.Mover.Move(p.path, pid); err == nil {
				w.Log.Info("process left its route group (desktop/systemd scope), moved back", "pid", pid, "app", comm(proc, pid), "from", cg)
			}
		}
		for _, child := range children(proc, pid) {
			if _, ok := snap[child]; ok {
				continue
			}
			cg := cgroupOf(proc, child)
			if cg != p.path && !strings.HasPrefix(cg, p.path+"/") && !outside(cg) {
				continue // in another Shunt group on purpose (shunt run inside)
			}
			if outside(cg) {
				_ = w.Mover.Move(p.path, child)
			}
			w.Place(child, p.path)
		}
	}
	if len(dead) > 0 {
		w.mu.Lock()
		for _, pid := range dead {
			delete(w.placed, pid)
		}
		w.mu.Unlock()
	}
}

func (w *Watcher) sticky(stop <-chan struct{}) {
	t := time.NewTicker(StickyInterval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			w.keepPlaced()
		}
	}
}

func startTime(proc string, pid int) string {
	b, err := os.ReadFile(filepath.Join(proc, strconv.Itoa(pid), "stat"))
	if err != nil {
		return ""
	}
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return ""
	}
	f := strings.Fields(s[i+1:])
	if len(f) < 20 {
		return ""
	}
	return f[19]
}

func cgroupOf(proc string, pid int) string {
	b, err := os.ReadFile(filepath.Join(proc, strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return ""
	}
	for _, l := range strings.Split(string(b), "\n") {
		if c, ok := strings.CutPrefix(l, "0::"); ok {
			return strings.Trim(c, "/")
		}
	}
	return ""
}

// children lists the child processes of pid (all threads).
func children(proc string, pid int) []int {
	tasks, err := os.ReadDir(filepath.Join(proc, strconv.Itoa(pid), "task"))
	if err != nil {
		return nil
	}
	var out []int
	for _, t := range tasks {
		b, err := os.ReadFile(filepath.Join(proc, strconv.Itoa(pid), "task", t.Name(), "children"))
		if err != nil {
			continue
		}
		for _, f := range strings.Fields(string(b)) {
			if c, err := strconv.Atoi(f); err == nil {
				out = append(out, c)
			}
		}
	}
	return out
}
