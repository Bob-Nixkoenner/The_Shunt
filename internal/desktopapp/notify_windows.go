package desktopapp

import (
	"os/exec"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/windows/registry"
)

// appID is the toast sender: registered once per user so the toast says
// "The Shunt" and not "Windows PowerShell".
const appID = "org.theshunt.app"

var registerOnce sync.Once

func registerAppID() {
	registerOnce.Do(func() {
		k, _, err := registry.CreateKey(registry.CURRENT_USER, `Software\Classes\AppUserModelId\`+appID, registry.SET_VALUE)
		if err != nil {
			return
		}
		defer k.Close()
		_ = k.SetStringValue("DisplayName", "The Shunt")
	})
}

// Notifier shows Windows toast notifications (through PowerShell, no extra
// dependencies).
type Notifier struct{}

func NewNotifier() *Notifier { return &Notifier{} }

// Notify shows a toast. Errors are ignored: a missing toast must not stop
// the app.
func (n *Notifier) Notify(x Notification) {
	registerAppID()
	esc := func(s string) string {
		s = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "'", "''").Replace(s)
		return s
	}
	script := `$ErrorActionPreference='Stop'
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
$x = New-Object Windows.Data.Xml.Dom.XmlDocument
$x.LoadXml('<toast><visual><binding template="ToastGeneric"><text>` + esc(x.Summary) + `</text><text>` + esc(x.Body) + `</text></binding></visual></toast>')
$id = '` + appID + `'
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($id).Show([Windows.UI.Notifications.ToastNotification]::new($x))`
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = cmd.Start()
	go cmd.Wait()
}
