//go:build !windows

package desktopapp

// PromoteTrayIcon: only Windows hides tray icons by default.
func PromoteTrayIcon(string) {}
