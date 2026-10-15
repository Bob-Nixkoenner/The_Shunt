//go:build !linux && !windows

package desktopapp

import "errors"

func AutostartEnabled() bool { return false }

func SetAutostart(bool, string) error {
	return errors.New("autostart is not supported on this platform")
}
