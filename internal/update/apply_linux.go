package update

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

// Apply runs the installer (the same one as Command) as root after a
// graphical password prompt (polkit). It runs on its own, so it survives the
// restart of this app; its output goes to LogFile().
func Apply(_ context.Context, tag string) error {
	if !verRe.MatchString(tag) {
		return ErrNotSupported // source build: the command builds from source
	}
	pk, err := exec.LookPath("pkexec")
	if err != nil {
		return fmt.Errorf("pkexec (polkit) not found - %w", ErrNotSupported)
	}
	log, err := os.OpenFile(LogFile(), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer log.Close()
	script := "curl -fsSL https://raw.githubusercontent.com/" + Repo + "/HEAD/install.sh | bash"
	cmd := exec.Command(pk, "env", "SHUNT_YES=1", "bash", "-c", script)
	cmd.Stdout, cmd.Stderr = log, log
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}

// LogFile is where the installer started by Apply writes its output.
func LogFile() string {
	d, err := os.UserConfigDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "shunt-update.log")
	}
	_ = os.MkdirAll(filepath.Join(d, "the-shunt"), 0o700)
	return filepath.Join(d, "the-shunt", "update.log")
}

func canApply() bool { _, err := exec.LookPath("pkexec"); return err == nil }
