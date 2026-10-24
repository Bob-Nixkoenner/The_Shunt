//go:build !windows

package desktop

import "os"

// dirLink makes link point to the directory target.
func dirLink(target, link string) error { return os.Symlink(target, link) }

func samePath(a, b string) bool { return a == b }
