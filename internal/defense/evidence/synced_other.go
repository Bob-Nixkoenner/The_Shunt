//go:build !linux

package evidence

// ClockSynced: not readable here.
func ClockSynced() (synced, known bool) { return false, false }
