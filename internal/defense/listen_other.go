//go:build !linux

package defense

// LinuxListen is the generic listener on other platforms (no mark, no
// interface binding).
func LinuxListen(func() string, uint32) ListenFunc { return DefaultListen }
