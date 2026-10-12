// Package desktop makes application menu entries start through a route.
//
// It writes a user-level copy of an app's .desktop file into
// ~/.local/share/applications whose Exec lines are prefixed with
// `shunt run --via <route> --`. The menu picks the user copy over the system
// one, so starting the app from the menu is race free (unlike app rules,
// which move a process after it started). Removing the copy restores the
// original entry. No root needed.
package desktop

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Bob-Nixkoenner/the_shunt/internal/argv"
)

// Keys Shunt writes into .desktop files it manages.
const (
	MarkerKey = "X-Shunt-Route" // the route; present on every managed file
	CloneKey  = "X-Shunt-Clone" // launchers: id of the app they start
	ArgsKey   = "X-Shunt-Args"  // launchers: extra arguments (command-line syntax)
)

// Entry is an application from the menu.
type Entry struct {
	ID    string `json:"id"` // file name without .desktop
	Name  string `json:"name"`
	Exec  string `json:"exec"`
	Icon  string `json:"icon,omitempty"`
	Route string `json:"route,omitempty"` // set when Shunt manages the entry
	// Online: the app's categories say it talks to the network (browser,
	// mail, chat, P2P...). Used to keep long menus (Kali!) manageable.
	Online bool `json:"online"`
	// Clone is set on extra launchers made by Clone: the source app id.
	Clone string `json:"clone,omitempty"`
	Args  string `json:"args,omitempty"`
	path  string
}

// Dirs returns the application directories in XDG precedence order (the
// user's own directory first).
func Dirs() []string {
	home, _ := os.UserHomeDir()
	dataHome := os.Getenv("XDG_DATA_HOME")
	if dataHome == "" {
		dataHome = filepath.Join(home, ".local", "share")
	}
	dataDirs := os.Getenv("XDG_DATA_DIRS")
	if dataDirs == "" {
		dataDirs = "/usr/local/share:/usr/share"
	}
	dirs := []string{filepath.Join(dataHome, "applications")}
	for _, d := range append(strings.Split(dataDirs, ":"),
		filepath.Join(dataHome, "flatpak", "exports", "share"), "/var/lib/flatpak/exports/share") {
		if d != "" {
			dirs = append(dirs, filepath.Join(d, "applications"))
		}
	}
	return dirs
}

func userDir() string { return Dirs()[0] }

// List returns the visible applications, sorted by name.
func List() ([]Entry, error) {
	seen := map[string]bool{}
	var out []Entry
	for _, dir := range Dirs() {
		files, _ := filepath.Glob(filepath.Join(dir, "*.desktop"))
		for _, f := range files {
			id := strings.TrimSuffix(filepath.Base(f), ".desktop")
			if seen[id] {
				continue
			}
			seen[id] = true
			kv, err := readMain(f)
			if err != nil || kv["Type"] != "Application" || kv["NoDisplay"] == "true" || kv["Hidden"] == "true" || kv["Exec"] == "" {
				continue
			}
			out = append(out, Entry{ID: id, Name: kv["Name"], Exec: kv["Exec"], Icon: kv["Icon"], Route: kv[MarkerKey], Online: online(kv["Categories"]) || kv[CloneKey] != "", Clone: kv[CloneKey], Args: kv[ArgsKey], path: f})
		}
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out, nil
}

// readMain parses the [Desktop Entry] group (unlocalized keys only).
func readMain(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	kv := map[string]string{}
	in := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(l, "[") {
			if in {
				break
			}
			in = l == "[Desktop Entry]"
			continue
		}
		if k, v, ok := strings.Cut(l, "="); ok && in && !strings.Contains(k, "[") {
			kv[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return kv, sc.Err()
}

// source finds the original (non-Shunt) file for id.
func source(id string) (string, error) {
	for i, dir := range Dirs() {
		f := filepath.Join(dir, id+".desktop")
		if _, err := os.Stat(f); err != nil {
			continue
		}
		if i == 0 {
			kv, err := readMain(f)
			if err != nil {
				return "", err
			}
			if kv[MarkerKey] == "" {
				return "", fmt.Errorf("%s is your own custom entry, not changing it", f)
			}
			continue // our copy: look for the original below it
		}
		return f, nil
	}
	return "", fmt.Errorf("no application %q found", id)
}

// SetRoute makes the menu entry id start through route. shunt is the path
// of the shunt binary used in the Exec lines.
func SetRoute(id, route, shunt string) error {
	if strings.ContainsAny(id, "/\x00") || strings.ContainsAny(route, " \t\n\"'\\") || route == "" {
		return errors.New("invalid id or route")
	}
	if kv, err := readMain(filepath.Join(userDir(), id+".desktop")); err == nil && kv[CloneKey] != "" {
		return cloneTo(id, kv[CloneKey], kv["Name"], kv[ArgsKey], route, shunt)
	}
	src, err := source(id)
	if err != nil {
		return err
	}
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	out := rewrite(string(b), route, shunt)
	if err := os.MkdirAll(userDir(), 0o755); err != nil {
		return err
	}
	dst := filepath.Join(userDir(), id+".desktop")
	tmp := dst + ".shunt-tmp"
	if err := os.WriteFile(tmp, []byte(out), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

// rewrite prefixes every Exec line and marks the main group.
func rewrite(content, route, shunt string) string {
	var b strings.Builder
	group := ""
	marked := false
	for _, l := range strings.Split(content, "\n") {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "[") {
			if group == "[Desktop Entry]" && !marked {
				fmt.Fprintf(&b, "%s=%s\nDBusActivatable=false\n", MarkerKey, route)
				marked = true
			}
			group = t
		}
		switch {
		case strings.HasPrefix(t, "Exec="):
			// Exec quoting (desktop entry spec): plain words need no quotes.
			fmt.Fprintf(&b, "Exec=%s run --via %s -- %s\n", shunt, route, strings.TrimPrefix(t, "Exec="))
			continue
		case group == "[Desktop Entry]" && (strings.HasPrefix(t, "DBusActivatable=") || strings.HasPrefix(t, MarkerKey+"=")):
			continue // replaced: D-Bus activation would bypass Exec
		}
		b.WriteString(l)
		b.WriteString("\n")
	}
	s := strings.TrimRight(b.String(), "\n") + "\n"
	if group == "[Desktop Entry]" && !marked {
		s += fmt.Sprintf("%s=%s\nDBusActivatable=false\n", MarkerKey, route)
	}
	return s
}

// Unset removes Shunt's copy of the entry, restoring the original.
func Unset(id string) error {
	f := filepath.Join(userDir(), id+".desktop")
	kv, err := readMain(f)
	if err != nil {
		return fmt.Errorf("%s has no Shunt entry", id)
	}
	if kv[MarkerKey] == "" {
		return fmt.Errorf("%s was not made by Shunt, not removing it", f)
	}
	return os.Remove(f)
}

// onlineCategories are freedesktop categories of apps that use the network.
var onlineCategories = map[string]bool{
	"Network": true, "WebBrowser": true, "Email": true, "Chat": true,
	"InstantMessaging": true, "IRCClient": true, "P2P": true, "FileTransfer": true,
	"News": true, "Feed": true, "VideoConference": true, "Telephony": true,
	"RemoteAccess": true, "Game": true,
}

func online(categories string) bool {
	for _, c := range strings.Split(categories, ";") {
		if onlineCategories[strings.TrimSpace(c)] {
			// Kali files its tools under X-Kali-* plus sometimes Network;
			// those are not apps one routes day to day.
			return !strings.Contains(categories, "X-Kali")
		}
	}
	return false
}

// Clone creates an additional menu entry that starts app srcID with extra
// arguments through route, e.g. "Firefox SM" = firefox --new-instance -P sm
// via tunnel:vps. It returns the new entry's id.
func Clone(srcID, name, args, route, shunt string) (string, error) {
	id := "shunt-" + slug(name)
	if id == "shunt-" {
		return "", errors.New("name needed")
	}
	if kv, err := readMain(filepath.Join(userDir(), id+".desktop")); err == nil && kv[MarkerKey] == "" {
		return "", fmt.Errorf("an entry %s exists and is not Shunt's", id)
	}
	return id, cloneTo(id, srcID, name, args, route, shunt)
}

func cloneTo(id, srcID, name, args, route, shunt string) error {
	if strings.ContainsAny(srcID, "/\x00") || strings.ContainsAny(route, " \t\n\"'\\") || route == "" {
		return errors.New("invalid app id or route")
	}
	name = strings.Join(strings.Fields(name), " ") // no newlines in keys
	args = strings.Join(strings.Fields(args), " ")
	src, err := source(srcID)
	if err != nil {
		return err
	}
	kv, err := readMain(src)
	if err != nil {
		return err
	}
	words, err := argv.Split(kv["Exec"])
	if err != nil || len(words) == 0 {
		return fmt.Errorf("cannot parse Exec of %s", srcID)
	}
	extra, err := argv.Split(args)
	if err != nil {
		return fmt.Errorf("arguments: %w", err)
	}
	cmd := []string{argv.DesktopQuote(shunt), "run", "--via", route, "--", argv.DesktopQuote(words[0])}
	for _, a := range extra {
		cmd = append(cmd, argv.DesktopQuote(a))
	}
	for _, w := range words[1:] {
		if len(w) == 2 && w[0] == '%' { // field code (%u, %F, ...) stays as is
			cmd = append(cmd, w)
			continue
		}
		cmd = append(cmd, argv.DesktopQuote(w))
	}
	var b strings.Builder
	b.WriteString("[Desktop Entry]\nType=Application\n")
	fmt.Fprintf(&b, "Name=%s\nExec=%s\n", name, strings.Join(cmd, " "))
	for _, k := range []string{"Icon", "Categories", "Terminal"} {
		if v := kv[k]; v != "" {
			fmt.Fprintf(&b, "%s=%s\n", k, v)
		}
	}
	fmt.Fprintf(&b, "Comment=%s via %s (The Shunt)\nDBusActivatable=false\n%s=%s\n%s=%s\n%s=%s\n",
		kv["Name"], route, MarkerKey, route, CloneKey, srcID, ArgsKey, args)
	if err := os.MkdirAll(userDir(), 0o755); err != nil {
		return err
	}
	dst := filepath.Join(userDir(), id+".desktop")
	if err := os.WriteFile(dst+".shunt-tmp", []byte(b.String()), 0o644); err != nil {
		return err
	}
	return os.Rename(dst+".shunt-tmp", dst)
}

func slug(s string) string {
	var b strings.Builder
	dash := false
	for _, c := range strings.ToLower(s) {
		switch {
		case c >= 'a' && c <= 'z' || c >= '0' && c <= '9':
			b.WriteRune(c)
			dash = false
		case !dash && b.Len() > 0:
			b.WriteByte('-')
			dash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

// FirefoxProfiles returns the profile names of the user's Firefox
// installations (deb, snap and flatpak locations).
func FirefoxProfiles() []string {
	home, _ := os.UserHomeDir()
	seen := map[string]bool{}
	var out []string
	for _, f := range []string{
		filepath.Join(home, ".mozilla", "firefox", "profiles.ini"),
		filepath.Join(home, "snap", "firefox", "common", ".mozilla", "firefox", "profiles.ini"),
		filepath.Join(home, ".var", "app", "org.mozilla.firefox", ".mozilla", "firefox", "profiles.ini"),
	} {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, l := range strings.Split(string(b), "\n") {
			if n, ok := strings.CutPrefix(strings.TrimSpace(l), "Name="); ok && n != "" && !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	sort.Strings(out)
	return out
}
