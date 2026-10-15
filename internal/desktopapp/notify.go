//go:build linux

package desktopapp

import (
	"github.com/godbus/dbus/v5"
)

// Notifier sends desktop notifications (org.freedesktop.Notifications).
type Notifier struct {
	conn *dbus.Conn
}

// NewNotifier connects to the session bus; Notify is a no-op if that fails.
func NewNotifier() *Notifier {
	c, err := dbus.SessionBus()
	if err != nil {
		return &Notifier{}
	}
	return &Notifier{conn: c}
}

// Notify shows a notification. Errors are ignored: no notification daemon
// must not stop the app.
func (n *Notifier) Notify(x Notification) {
	if n.conn == nil {
		return
	}
	urgency := byte(1)
	timeout := int32(6000)
	if x.Urgent {
		urgency, timeout = 2, int32(-1)
	}
	obj := n.conn.Object("org.freedesktop.Notifications", "/org/freedesktop/Notifications")
	obj.Call("org.freedesktop.Notifications.Notify", 0,
		"The Shunt", uint32(0), "network-vpn", x.Summary, x.Body, []string{},
		map[string]dbus.Variant{"urgency": dbus.MakeVariant(urgency)}, timeout)
}
