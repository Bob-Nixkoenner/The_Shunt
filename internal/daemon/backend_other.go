//go:build !linux

package daemon

// DefaultBackend: no backend for this platform yet.
func DefaultBackend() Backend { return nil }
