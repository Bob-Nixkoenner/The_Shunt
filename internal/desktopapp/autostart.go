package desktopapp

import (
	"fmt"
	"os"
	"path/filepath"
)

// AutostartFile is the XDG autostart entry of the desktop app.
func AutostartFile() string {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "autostart", "the-shunt.desktop")
}

// AutostartEnabled reports whether the app starts at login.
func AutostartEnabled() bool {
	_, err := os.Stat(AutostartFile())
	return err == nil
}

// SetAutostart enables (tray only, no window) or disables start at login.
func SetAutostart(on bool, exe string) error {
	f := AutostartFile()
	if !on {
		err := os.Remove(f)
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
		return err
	}
	return os.WriteFile(f, []byte(fmt.Sprintf(`[Desktop Entry]
Type=Application
Name=The Shunt (tray)
Comment=Shows whether your tunnels protect you
Exec=%s --hidden
Icon=the-shunt
Terminal=false
X-GNOME-Autostart-enabled=true
`, exe)), 0o644)
}
