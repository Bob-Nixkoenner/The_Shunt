//go:build !linux

package netdetect

// Current is not implemented on this platform yet: no profile matches.
func Current() Info { return Info{} }
