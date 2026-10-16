//go:build !linux

package tunnel

import (
	"errors"
	"log/slog"
)

// StartTailscale is not implemented on this platform yet.
func StartTailscale(TailscaleSpec, *slog.Logger, func()) (Device, error) {
	return nil, errors.New("Tailscale tunnels are not supported on this platform yet")
}
