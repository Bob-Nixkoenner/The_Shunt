//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// A hardened umask must not make the file unreadable for normal users.
func TestWriteReadableIgnoresUmask(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	p := filepath.Join(t.TempDir(), "nsswitch.conf")
	if err := writeReadable(p, []byte("hosts: files dns\n")); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v, want 0644", st.Mode().Perm())
	}
}
