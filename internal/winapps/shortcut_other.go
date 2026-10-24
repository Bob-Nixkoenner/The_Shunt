//go:build !windows

package winapps

import "errors"

// MakeShortcut: Start menu shortcuts exist on Windows only.
func MakeShortcut(Shortcut) error { return errors.New("shortcuts: Windows only") }
