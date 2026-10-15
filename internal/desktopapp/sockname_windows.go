package desktopapp

import (
	"os"
	"path/filepath"
)

// No abstract sockets on Windows: a socket file in the user's own profile
// (only that user can reach it).
func defaultSocketName() string {
	dir := filepath.Join(os.Getenv("LOCALAPPDATA"), "Shunt")
	_ = os.MkdirAll(dir, 0o700)
	return filepath.Join(dir, "app.sock")
}
