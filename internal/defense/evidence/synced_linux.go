//go:build linux

package evidence

import "golang.org/x/sys/unix"

const staUnsync = 0x40 // STA_UNSYNC

// ClockSynced reads the kernel's clock state with adjtimex in read-only
// mode (modes = 0); it changes nothing.
func ClockSynced() (synced, known bool) {
	var tx unix.Timex
	st, err := unix.Adjtimex(&tx)
	if err != nil {
		return false, false
	}
	return st != unix.TIME_ERROR && tx.Status&staUnsync == 0, true
}
