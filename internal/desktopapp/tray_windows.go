package desktopapp

import (
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

// PromoteTrayIcon asks Windows 11 to show this program's tray icon next to
// the clock instead of hiding it behind the "^" arrow (the user can still
// hide it again: Settings > Personalization > Taskbar). Windows creates the
// setting when the icon first appears, so this retries for a while. The icon
// is the only way to see at a glance that the tunnels protect you.
func PromoteTrayIcon(exe string) {
	const root = `Control Panel\NotifyIconSettings`
	// Windows stores Program Files paths as {KnownFolderGUID}\dir\app.exe,
	// so compare by file name
	suffix := `\` + strings.ToLower(filepath.Base(exe))
	found := false
	for range 20 {
		time.Sleep(2 * time.Second)
		k, err := registry.OpenKey(registry.CURRENT_USER, root, registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			continue
		}
		names, _ := k.ReadSubKeyNames(-1)
		k.Close()
		for _, n := range names {
			sk, err := registry.OpenKey(registry.CURRENT_USER, root+`\`+n, registry.QUERY_VALUE|registry.SET_VALUE)
			if err != nil {
				continue
			}
			path, _, _ := sk.GetStringValue("ExecutablePath")
			if lp := strings.ToLower(path); strings.EqualFold(path, exe) || strings.HasSuffix(lp, suffix) {
				found = true
				if _, _, err := sk.GetIntegerValue("IsPromoted"); err != nil { // never decided: promote once; a later "hide" by the user stays
					_ = sk.SetDWordValue("IsPromoted", 1)
				}
			}
			sk.Close()
		}
		if found {
			return
		}
	}
}
