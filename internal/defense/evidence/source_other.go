//go:build !linux

package evidence

import (
	"context"
	"errors"
)

// CaptureSupported says whether this platform has a packet source.
const CaptureSupported = false

// RunControl: no packet capture on this platform (event log and export only).
func RunControl(context.Context, string, *Capture) error {
	return errors.New("packet capture is Linux-only")
}
