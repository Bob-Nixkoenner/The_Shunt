//go:build !linux && !windows

package update

import "context"

// Apply is not available here; the update is done by hand (Info.Command).
func Apply(context.Context, string) error { return ErrNotSupported }

func canApply() bool { return false }
