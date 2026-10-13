//go:build !linux

package tunnel

import (
	"errors"
	"log/slog"
)

// StartOpenVPN is not implemented on this platform yet.
func StartOpenVPN(OpenVPNSpec, *slog.Logger, func()) (Device, error) {
	return nil, errors.New("OpenVPN tunnels are not supported on this platform yet")
}
