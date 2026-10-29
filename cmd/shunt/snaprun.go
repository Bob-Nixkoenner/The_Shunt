package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/api"
	"github.com/Bob-Nixkoenner/the_shunt/internal/i18n"
)

// snapApp: the command starts a snap ("/snap/bin/brave", possibly behind
// "env VAR=x"). Most snaps start fine inside a route, but some (Brave,
// Vivaldi, Opera GX) make snap-confine refuse our cgroup with "... is not a
// snap cgroup": it wants one of its own while it sets the sandbox up.
func snapApp(cmd []string) bool {
	i := 0
	if filepath.Base(cmd[0]) == "env" {
		for i = 1; i < len(cmd) && (strings.Contains(cmd[i], "=") || strings.HasPrefix(cmd[i], "-")); i++ {
		}
	}
	if i >= len(cmd) {
		return false
	}
	t := cmd[i]
	if strings.HasPrefix(t, "/snap/bin/") {
		return true
	}
	if strings.Contains(t, "/") {
		return false
	}
	p, err := exec.LookPath(t)
	return err == nil && strings.HasPrefix(p, "/snap/bin/")
}

// runSnapCmd starts the snap the normal way (the process is in its route
// from the first instruction on). If snap-confine refuses that cgroup, the
// app is started again the other way, see runSnap.
func runSnapCmd(c *api.Client, group string, cmd []string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	args := append([]string{"-s", socketPath, "run", "-placed", "-group", group, "--"}, cmd...)
	child := exec.Command(self, args...)
	child.Stdin, child.Stdout = os.Stdin, os.Stdout
	errPipe, err := child.StderrPipe()
	if err != nil {
		return err
	}
	if err := child.Start(); err != nil {
		return err
	}
	var refused atomic.Bool
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := errPipe.Read(buf)
			if n > 0 {
				if strings.Contains(string(buf[:n]), "is not a snap cgroup") {
					refused.Store(true)
				} else {
					os.Stderr.Write(buf[:n])
				}
			}
			if err != nil {
				return
			}
		}
	}()
	err = child.Wait()
	if err != nil && refused.Load() {
		return runSnap(c, group, cmd)
	}
	return exitStatus(err)
}

// runSnap starts the command as it is and moves the process into the group
// the moment it has become the app itself (after snap-confine and snap-exec,
// before the app opens its first connection: that takes it far longer than
// the poll interval). Children forked in between are moved too.
func runSnap(c *api.Client, group string, cmd []string) error {
	child := exec.Command(cmd[0], cmd[1:]...)
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := child.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- child.Wait() }()
	pid := child.Process.Pid
	adopt := func(pids ...int) int {
		var res struct{ Moved int }
		if err := c.Do("POST", "/v1/adopt", api.AdoptRequest{Group: group, PIDs: pids}, &res); err != nil {
			return -1
		}
		return res.Moved
	}
	deadline := time.Now().Add(20 * time.Second)
	scope := ""
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			return exitStatus(err) // ended before it ever was the app: nothing to route
		default:
		}
		if isAppExe(procImage(pid)) {
			scope = cgroupOf(pid)
			if n := adopt(pid); n <= 0 {
				// never leave an app running outside the route it was asked for
				_ = child.Process.Kill()
				if n < 0 {
					return errors.New(i18n.T("shuntd refused to move the app into the route"))
				}
				return errors.New(i18n.T("could not move {cmd} into {group}", "cmd", cmd[0], "group", group))
			}
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if scope == "" {
		_ = child.Process.Kill()
		return errors.New(i18n.T("{cmd} did not start in time", "cmd", cmd[0]))
	}
	// children that were forked before the move stay in the snap's own scope
	for end := time.Now().Add(3 * time.Second); time.Now().Before(end); time.Sleep(25 * time.Millisecond) {
		if pids := scopePIDs(scope); len(pids) > 0 {
			adopt(pids...)
		}
	}
	return exitStatus(<-done)
}

// procImage is the program a process runs. /proc/<pid>/exe is closed to us
// once snap-confine has changed the process' credentials, so the first word
// of the command line serves as the fallback.
func procImage(pid int) string {
	if exe, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe"); err == nil && !strings.HasSuffix(exe, "/bash") && !strings.HasSuffix(exe, "/sh") && !strings.HasSuffix(exe, "/dash") {
		return exe
	}
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if err != nil {
		return ""
	}
	w := strings.Split(string(b), "\x00")
	// a launcher script of the snap ("/bin/bash /snap/brave/696/.../brave-browser"): the script is the app
	switch filepath.Base(w[0]) {
	case "bash", "sh", "dash", "python3", "python", "perl":
		for _, a := range w[1:] {
			if !strings.HasPrefix(a, "-") {
				return a
			}
		}
	}
	return w[0]
}

// isAppExe: the process image is the snap's own program, not the snap tooling.
func isAppExe(exe string) bool {
	exe = strings.TrimSuffix(exe, " (deleted)")
	return strings.HasPrefix(exe, "/snap/") && !strings.HasPrefix(exe, "/snap/bin/") && !strings.Contains(exe, "/usr/lib/snapd/") && !strings.HasSuffix(exe, "/usr/bin/snap")
}

func cgroupOf(pid int) string {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cgroup")
	if err != nil {
		return ""
	}
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "0::") {
			return strings.TrimPrefix(l, "0::")
		}
	}
	return ""
}

func scopePIDs(cg string) []int {
	b, err := os.ReadFile(filepath.Join("/sys/fs/cgroup", cg, "cgroup.procs"))
	if err != nil {
		return nil
	}
	var out []int
	for _, f := range strings.Fields(string(b)) {
		if n, err := strconv.Atoi(f); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func exitStatus(err error) error {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		os.Exit(ee.ExitCode())
	}
	return err
}
