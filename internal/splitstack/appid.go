package splitstack

import "strings"

// App IDs: the platform's Owner returns a full path on Windows
// (c:\program files\mozilla firefox\firefox.exe). A key in the config may be
// that path or just the file name ("firefox.exe"), which matches the program
// wherever it is installed. Android IDs (package names) never contain a
// separator and match exactly.

func appBase(app string) string {
	if i := strings.LastIndexAny(app, `\/`); i >= 0 {
		return app[i+1:]
	}
	return ""
}

func appInSet(m map[string]bool, app string) bool {
	if m[app] {
		return true
	}
	if b := appBase(app); b != "" {
		return m[b]
	}
	return false
}

func appRoute(m map[string]string, app string) (string, bool) {
	if r, ok := m[app]; ok {
		return r, true
	}
	if b := appBase(app); b != "" {
		r, ok := m[b]
		return r, ok
	}
	return "", false
}

// CheckConfig parses and validates a config (what New and SetRules check
// first), without starting anything.
func CheckConfig(configJSON string) error {
	_, err := parseConfig(configJSON)
	return err
}
