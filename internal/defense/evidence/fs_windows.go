//go:build windows

package evidence

import "os"

// Windows has no O_NOFOLLOW; the directory is checked with Lstat instead.
const oNoFollow = 0

func ownedByUs(os.FileInfo) bool { return true }
