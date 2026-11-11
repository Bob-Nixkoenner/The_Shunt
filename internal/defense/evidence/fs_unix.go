//go:build !windows

package evidence

import (
	"os"
	"syscall"
)

const oNoFollow = syscall.O_NOFOLLOW

// ownedByUs reports whether fi belongs to the current user.
func ownedByUs(fi os.FileInfo) bool {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid) == os.Geteuid()
	}
	return true
}
