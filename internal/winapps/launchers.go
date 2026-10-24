package winapps

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/Bob-Nixkoenner/the_shunt/internal/desktop"
)

// Launchers are extra Start menu entries that start a program with extra
// arguments in a route ("Brave Bob" = brave.exe --user-data-dir=… via
// tunnel:vps), as menu entries do on Linux. Each is a shortcut to
// `shunt-desktop.exe run --via ROUTE -- PROGRAM ARGS`; what they are is kept
// in launchers.json next to them, the shortcuts are made from it.

// MenuFolder is the Start menu folder of the launchers. StartMenu skips it:
// they are not programs of their own.
const MenuFolder = "The Shunt Launchers"

// Launcher is one extra Start menu entry.
type Launcher struct {
	ID    string `json:"id"`    // "shunt-" + slug of the name, as on Linux
	Name  string `json:"name"`  // Start menu name
	App   string `json:"app"`   // program ID it starts ("brave.exe")
	Exe   string `json:"exe"`   // full path of that program
	Args  string `json:"args"`  // extra arguments, Windows command-line syntax
	Route string `json:"route"` // route it starts in
}

var launchMu sync.Mutex

func (s *Source) launcherFile() string {
	dir := s.LauncherDir
	if dir == "" {
		dir = filepath.Join(os.Getenv("APPDATA"), "Shunt")
	}
	return filepath.Join(dir, "launchers.json")
}

func (s *Source) menuDir() string {
	if s.MenuDir != "" {
		return s.MenuDir
	}
	return filepath.Join(os.Getenv("APPDATA"), `Microsoft\Windows\Start Menu\Programs`, MenuFolder)
}

func (s *Source) loadLaunchers() ([]Launcher, error) {
	b, err := os.ReadFile(s.launcherFile())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var ls []Launcher
	if err := json.Unmarshal(b, &ls); err != nil {
		return nil, fmt.Errorf("%s: %w", s.launcherFile(), err)
	}
	return ls, nil
}

func (s *Source) saveLaunchers(ls []Launcher) error {
	f := s.launcherFile()
	if err := os.MkdirAll(filepath.Dir(f), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(ls, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(f+".tmp", b, 0o600); err != nil {
		return err
	}
	return os.Rename(f+".tmp", f)
}

// lnkPath is where the shortcut of l lives (its name is what the Start menu shows).
func (s *Source) lnkPath(l Launcher) string {
	name := strings.Map(func(r rune) rune {
		if strings.ContainsRune(`\/:*?"<>|`, r) || r < 32 {
			return '-'
		}
		return r
	}, l.Name)
	return filepath.Join(s.menuDir(), name+".lnk")
}

// command is what the shortcut runs: arguments for Self.
func (s *Source) command(l Launcher) string {
	a := "run --via " + l.Route + " -- " + winQuote(l.Exe)
	if l.Args != "" {
		a += " " + l.Args
	}
	return a
}

func (s *Source) writeLnk(l Launcher) error {
	if s.Self == "" {
		return errors.New("launchers: path of shunt-desktop unknown")
	}
	if err := os.MkdirAll(s.menuDir(), 0o755); err != nil {
		return err
	}
	mk := s.Shortcut
	if mk == nil {
		mk = MakeShortcut
	}
	return mk(Shortcut{
		Path: s.lnkPath(l), Target: s.Self, Args: s.command(l), Dir: filepath.Dir(l.Exe),
		Icon: l.Exe + ",0", Description: l.Name + " via " + l.Route + " (The Shunt)",
	})
}

// Shortcut is a .lnk file to write.
type Shortcut struct {
	Path, Target, Args, Dir, Icon, Description string
}

func validRoute(route string) error {
	if route == "" || strings.ContainsAny(route, " \t\r\n\"'\\") {
		return errors.New("invalid route")
	}
	return nil
}

// validArgs: the arguments go into the shortcut as they are; they must be one
// line with balanced quotes.
func validArgs(args string) error {
	if strings.ContainsAny(args, "\r\n\x00") || strings.Count(args, `"`)%2 != 0 {
		return errors.New("arguments: one line, quotes in pairs")
	}
	return nil
}

// Clone makes a launcher for program app (an ID of the list) with extra
// arguments in route, like desktop.Clone on Linux. It returns its ID.
func (s *Source) Clone(app, name, args, route string) (string, error) {
	name = strings.Join(strings.Fields(name), " ")
	args = strings.TrimSpace(args)
	id := "shunt-" + desktop.Slug(name)
	if id == "shunt-" {
		return "", errors.New("name needed")
	}
	if err := validRoute(route); err != nil {
		return "", err
	}
	if err := validArgs(args); err != nil {
		return "", err
	}
	exe := ""
	if list, err := s.programs(); err == nil {
		for _, e := range list {
			if e.ID == strings.ToLower(app) && e.Exec != "" {
				exe = e.Exec
			}
		}
	}
	if exe == "" {
		return "", fmt.Errorf("no program %q found (start it once or add it to the Start menu)", app)
	}
	launchMu.Lock()
	defer launchMu.Unlock()
	ls, err := s.loadLaunchers()
	if err != nil {
		return "", err
	}
	for _, l := range ls {
		if l.ID == id {
			return "", fmt.Errorf("a launcher %q exists already", l.Name)
		}
	}
	l := Launcher{ID: id, Name: name, App: strings.ToLower(app), Exe: exe, Args: args, Route: route}
	if err := s.writeLnk(l); err != nil {
		return "", err
	}
	if err := s.saveLaunchers(append(ls, l)); err != nil {
		_ = os.Remove(s.lnkPath(l))
		return "", err
	}
	return id, nil
}

// setLauncher changes the route of launcher id ("" removes it); found is
// false when id is no launcher.
func (s *Source) setLauncher(id, route string) (found bool, err error) {
	launchMu.Lock()
	defer launchMu.Unlock()
	ls, err := s.loadLaunchers()
	if err != nil {
		return false, err
	}
	for i, l := range ls {
		if l.ID != id {
			continue
		}
		if route == "" {
			// the shortcut only: a profile folder (and the junction in it) stays
			if err := os.Remove(s.lnkPath(l)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return true, err
			}
			return true, s.saveLaunchers(append(ls[:i:i], ls[i+1:]...))
		}
		if err := validRoute(route); err != nil {
			return true, err
		}
		l.Route = route
		if err := s.writeLnk(l); err != nil {
			return true, err
		}
		ls[i] = l
		return true, s.saveLaunchers(ls)
	}
	return false, nil
}

// launcherEntries are the launchers as list entries (Clone/Args set, Exec =
// the command the UI shows and starts: after "--" comes the program).
func (s *Source) launcherEntries() []desktop.Entry {
	ls, _ := s.loadLaunchers()
	out := make([]desktop.Entry, 0, len(ls))
	for _, l := range ls {
		out = append(out, desktop.Entry{ID: l.ID, Name: l.Name, Exec: winQuote(s.Self) + " " + s.command(l),
			Route: l.Route, Online: true, Clone: l.App, Args: l.Args})
	}
	return out
}

// winQuote quotes one argument the way Windows programs split their command
// line (CommandLineToArgvW rules).
func winQuote(a string) string {
	if a != "" && !strings.ContainsAny(a, " \t\"") {
		return a
	}
	var b strings.Builder
	b.WriteByte('"')
	slashes := 0
	for _, c := range a {
		switch c {
		case '\\':
			slashes++
			continue
		case '"':
			b.WriteString(strings.Repeat(`\`, slashes*2+1))
		default:
			b.WriteString(strings.Repeat(`\`, slashes))
		}
		slashes = 0
		b.WriteRune(c)
	}
	b.WriteString(strings.Repeat(`\`, slashes*2))
	b.WriteByte('"')
	return b.String()
}
