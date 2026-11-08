package update

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// Apply runs the installer of release tag as root after a graphical
// password prompt (polkit). Only the installer the release signed runs:
// install.sh is a release asset listed in the signed SHA256SUMS, it is
// downloaded and checked here (Download), and checked again as root after
// copying it to a private root directory, so it cannot be swapped in
// between. It runs on its own, so it survives the restart of this app; its
// output goes to LogFile().
func Apply(ctx context.Context, tag string) error {
	if !verRe.MatchString(tag) {
		return ErrNotSupported // source build: the command builds from source
	}
	pk, err := exec.LookPath("pkexec")
	if err != nil {
		return fmt.Errorf("pkexec (polkit) not found - %w", ErrNotSupported)
	}
	path, sum, err := download(ctx, tag, "install.sh")
	if err == nil && !sumRe.MatchString(sum) {
		err = fmt.Errorf("bad checksum %q", sum)
	}
	if err != nil {
		return fmt.Errorf("the installer of %s could not be verified, nothing was installed (update with the command instead): %w", tag, err)
	}
	log, err := os.OpenFile(LogFile(), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer log.Close()
	cmd := exec.Command(pk, installerArgs(path, sum, tag)...)
	cmd.Stdout, cmd.Stderr = log, log
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	writePid(cmd.Process.Pid)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	// pkexec waits for the password, so an early end means it could not ask
	// (no polkit agent, wrong session) or the user cancelled
	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("the installer did not start: %s", lastLine(LogFile(), err))
		}
	case <-time.After(3 * time.Second):
	}
	return nil
}

// rootScript runs as root: copy the installer ($1) into a new private
// directory (also so that its directory holds no go.mod someone else put
// there), check it against the signed hash ($2) and run it for release $3.
const rootScript = `set -u
d=$(mktemp -d) || exit 1
trap 'rm -rf "$d"' EXIT
head -c 4194304 -- "$1" >"$d/install.sh" || exit 1
if ! printf '%s  %s\n' "$2" "$d/install.sh" | sha256sum -c --quiet - >/dev/null 2>&1; then
	echo "install.sh does not match the signed checksum - nothing was installed" >&2
	exit 1
fi
SHUNT_YES=1 SHUNT_REF="$3" SHUNT_RELEASE_INSTALLER=1 bash "$d/install.sh"`

var sumRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// installerArgs are pkexec's arguments for Apply.
func installerArgs(path, sum, tag string) []string {
	return []string{"bash", "-c", rootScript, "shunt-update", path, sum, tag}
}

// lastLine returns the last line of the log file (the reason pkexec gave).
func lastLine(path string, fallback error) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return fallback.Error()
	}
	l := strings.Split(strings.TrimSpace(string(b)), "\n")
	if last := strings.TrimSpace(l[len(l)-1]); last != "" {
		return last
	}
	return fallback.Error()
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
