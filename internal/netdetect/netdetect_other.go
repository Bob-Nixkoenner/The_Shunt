//go:build !linux && !windows

package netdetect

// Current is not implemented on this platform yet: no profile matches.
func Current() Info { return WithPublic(Info{}) }
