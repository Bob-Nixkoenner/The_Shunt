//go:build !linux

package update

// GetProgress: only Linux installs updates through a logged installer.
func GetProgress() Progress { return Progress{State: "idle", Total: len(installSteps)} }
