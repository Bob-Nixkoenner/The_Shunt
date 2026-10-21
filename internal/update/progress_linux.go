package update

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// GetProgress reads the installer's output (LogFile) and checks that the
// installer still lives (PidFile). It also works after the app restarted.
func GetProgress() Progress {
	b, err := os.ReadFile(LogFile())
	if err != nil {
		return Progress{State: "idle", Total: len(installSteps)}
	}
	var mt time.Time
	if fi, err := os.Stat(LogFile()); err == nil {
		mt = fi.ModTime()
	}
	return parseProgress(string(b), pidAlive(), time.Since(mt), LogFile())
}

// PidFile holds the pid of the installer started by Apply (pkexec, which
// stays until the installer ends).
func PidFile() string { return LogFile() + ".pid" }

func writePid(pid int) {
	_ = os.WriteFile(PidFile(), []byte(strconv.Itoa(pid)), 0o600)
}

func pidAlive() bool {
	b, err := os.ReadFile(PidFile())
	if err != nil {
		return false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 {
		return false
	}
	// pkexec runs as root: kill(pid, 0) would say EPERM, /proc tells enough
	_, err = os.Stat("/proc/" + strconv.Itoa(pid))
	return err == nil
}
