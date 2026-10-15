//go:build !windows

package winapps

// Running: no process list on this platform.
func Running() []string { return nil }
