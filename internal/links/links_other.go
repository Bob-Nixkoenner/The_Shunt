//go:build !linux

package links

// Current is not implemented on this platform yet: no link is connected,
// so link routes block.
func Current() State { return State{} }
