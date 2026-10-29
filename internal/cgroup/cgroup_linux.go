package cgroup

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Mount locates the cgroup2 mount point. Pure cgroup v2 systems (Pop!_OS
// 22.04+) have it at /sys/fs/cgroup, hybrid ones at /sys/fs/cgroup/unified.
func Mount() (string, error) {
	for _, p := range []string{"/sys/fs/cgroup", "/sys/fs/cgroup/unified"} {
		var st unix.Statfs_t
		if err := unix.Statfs(p, &st); err == nil && st.Type == unix.CGROUP2_SUPER_MAGIC {
			return p, nil
		}
	}
	return "", fmt.Errorf("no cgroup2 mount found")
}

// Self returns the cgroup v2 path of the current process, relative to the mount.
func Self() (string, error) {
	f, err := os.Open("/proc/self/cgroup")
	if err != nil {
		return "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if p, ok := strings.CutPrefix(sc.Text(), "0::"); ok {
			return strings.Trim(p, "/"), nil
		}
	}
	return "", fmt.Errorf("no cgroup v2 entry in /proc/self/cgroup")
}

// Manager creates cgroups and moves processes below its mount.
type Manager struct {
	Mount string
}

func (m Manager) abs(rel string) string { return filepath.Join(m.Mount, rel) }

// Ensure creates a cgroup (and parents).
func (m Manager) Ensure(rel string) error {
	return os.MkdirAll(m.abs(rel), 0o755)
}

// Move places a process into a cgroup. Children it forks later inherit it;
// sockets it already has keep their old cgroup.
func (m Manager) Move(rel string, pid int) error {
	return os.WriteFile(filepath.Join(m.abs(rel), "cgroup.procs"), []byte(strconv.Itoa(pid)), 0)
}

// Procs lists the PIDs directly in a cgroup.
func (m Manager) Procs(rel string) ([]int, error) {
	b, err := os.ReadFile(filepath.Join(m.abs(rel), "cgroup.procs"))
	if err != nil {
		return nil, err
	}
	var out []int
	for _, l := range strings.Fields(string(b)) {
		if n, err := strconv.Atoi(l); err == nil {
			out = append(out, n)
		}
	}
	return out, nil
}

// Kill ends every process in the cgroup and its children (cgroup.kill,
// kernel 5.14+). It needs no CAP_KILL, which shuntd's unit does not have.
func (m Manager) Kill(rel string) error {
	return os.WriteFile(filepath.Join(m.abs(rel), "cgroup.kill"), []byte("1"), 0)
}

// Remove deletes an empty cgroup (errors are ignored by most callers: a
// group that still has processes simply stays).
func (m Manager) Remove(rel string) error { return os.Remove(m.abs(rel)) }
