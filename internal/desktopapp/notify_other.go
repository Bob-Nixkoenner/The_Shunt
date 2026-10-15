//go:build !linux && !windows

package desktopapp

// Notifier: no desktop notifications on this platform.
type Notifier struct{}

func NewNotifier() *Notifier { return &Notifier{} }

func (n *Notifier) Notify(Notification) {}
