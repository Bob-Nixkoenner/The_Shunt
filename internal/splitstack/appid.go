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

// Pinned app IDs: a process started in a route (Windows: `shunt-desktop run`,
// a job object of the service) is reported as PinnedPref + route + ">" + its
// path. The route goes with the process and its children, like a cgroup on
// Linux; the path still selects app rules, domain rules and the DNS filter.
const PinnedPref = "run:"

// Pinned makes the app ID of a process pinned to route.
func Pinned(route, app string) string { return PinnedPref + route + ">" + app }

// splitPinned returns the route a pinned ID carries ("" = not pinned) and
// the app ID without it.
func splitPinned(id string) (route, app string) {
	rest, ok := strings.CutPrefix(id, PinnedPref)
	if !ok {
		return "", id
	}
	route, app, ok = strings.Cut(rest, ">")
	if !ok || route == "" {
		return "", id
	}
	return route, app
}
