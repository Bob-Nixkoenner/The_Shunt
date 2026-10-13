package desktop

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/Bob-Nixkoenner/the_shunt/internal/sqlitelite"
)

// FirefoxProfile is a Firefox profile of the current user.
type FirefoxProfile struct {
	Name string `json:"name"`
	Path string `json:"path"` // absolute profile directory
}

// firefoxRoots lists where Firefox keeps its profiles, depending on the
// platform and how Firefox was installed (deb, snap, flatpak, newer XDG).
func firefoxRoots() []string {
	home, _ := os.UserHomeDir()
	switch runtime.GOOS {
	case "windows":
		return []string{filepath.Join(os.Getenv("APPDATA"), "Mozilla", "Firefox")}
	case "darwin":
		return []string{filepath.Join(home, "Library", "Application Support", "Firefox")}
	}
	cfg := os.Getenv("XDG_CONFIG_HOME")
	if cfg == "" {
		cfg = filepath.Join(home, ".config")
	}
	return []string{
		filepath.Join(cfg, "mozilla", "firefox"),                                // newer Firefox (XDG)
		filepath.Join(home, ".mozilla", "firefox"),                              // deb, tarball, ESR
		filepath.Join(home, "snap", "firefox", "common", ".mozilla", "firefox"), // Ubuntu snap
		filepath.Join(home, "snap", "firefox", "common", ".config", "mozilla", "firefox"),
		filepath.Join(home, ".var", "app", "org.mozilla.firefox", ".mozilla", "firefox"), // flatpak
		filepath.Join(home, ".var", "app", "org.mozilla.firefox", "config", "mozilla", "firefox"),
	}
}

// FirefoxProfiles lists the profiles of every Firefox installation found:
// the classic ones (profiles.ini) and the ones of Firefox's newer profile
// manager (named in "Profile Groups/*.sqlite"), which win on the name.
func FirefoxProfiles() []FirefoxProfile { return firefoxProfilesIn(firefoxRoots()) }

func firefoxProfilesIn(roots []string) []FirefoxProfile {
	byPath := map[string]string{}
	for _, root := range roots {
		for path, name := range iniProfiles(root) {
			if _, ok := byPath[path]; !ok {
				byPath[path] = name
			}
		}
		for path, name := range groupProfiles(root) {
			byPath[path] = name
		}
	}
	out := make([]FirefoxProfile, 0, len(byPath))
	for path, name := range byPath {
		if st, err := os.Stat(path); err == nil && st.IsDir() {
			out = append(out, FirefoxProfile{Name: name, Path: path})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Path < out[j].Path
	})
	return out
}

func profileDir(root, p string) string {
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	return filepath.Join(root, filepath.FromSlash(p))
}

// iniProfiles reads profiles.ini: path -> name.
func iniProfiles(root string) map[string]string {
	out := map[string]string{}
	b, err := os.ReadFile(filepath.Join(root, "profiles.ini"))
	if err != nil {
		return out
	}
	var name, path string
	flush := func() {
		if name != "" && path != "" {
			out[profileDir(root, path)] = name
		}
		name, path = "", ""
	}
	for _, l := range strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n") {
		l = strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(l, "["):
			flush()
		case strings.HasPrefix(l, "Name="):
			name = strings.TrimPrefix(l, "Name=")
		case strings.HasPrefix(l, "Path="):
			path = strings.TrimPrefix(l, "Path=")
		}
	}
	flush()
	return out
}

// groupProfiles reads the newer profile manager's databases: path -> name.
func groupProfiles(root string) map[string]string {
	out := map[string]string{}
	dbs, _ := filepath.Glob(filepath.Join(root, "Profile Groups", "*.sqlite"))
	for _, db := range dbs {
		rows, err := sqlitelite.Rows(db, "Profiles")
		if err != nil {
			continue
		}
		for _, r := range rows {
			path, _ := r["path"].(string)
			name, _ := r["name"].(string)
			if path != "" && name != "" {
				out[profileDir(root, path)] = name
			}
		}
	}
	return out
}
