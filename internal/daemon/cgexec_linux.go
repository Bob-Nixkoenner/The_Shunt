package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// CgroupExec implements `shuntd cgexec <cgroup dir> <program> [args…]`. The
// daemon's unit filters clone3 (so CLONE_INTO_CGROUP is out); instead the
// child moves itself into the group and then replaces itself by the program.
func CgroupExec(args []string) error {
	if len(args) < 2 {
		return errors.New("usage: shuntd cgexec <cgroup dir> <program> [args…]")
	}
	if err := os.WriteFile(filepath.Join(args[0], "cgroup.procs"), []byte("0"), 0); err != nil {
		return err
	}
	return syscall.Exec(args[1], args[1:], os.Environ())
}
