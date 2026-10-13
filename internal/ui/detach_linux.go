package ui

import (
	"os/exec"
	"syscall"
)

// detach starts cmd in its own session: it outlives the UI process.
func detach(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} }
