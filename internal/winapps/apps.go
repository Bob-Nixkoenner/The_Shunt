// Package winapps is the "Menu apps" list of the web UI on Windows: the
// programs that run right now plus the ones that have a rule, each with its
// route. A route is a rule in shunt.toml that matches the program by its
// file name (see internal/winsvc.Translate).
package winapps

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/api"
	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/Bob-Nixkoenner/the_shunt/internal/desktop"
)

// RulePrefix marks the rules this list manages ("app firefox.exe").
const RulePrefix = "app "

// Client is what the list needs from the service API.
type Client interface {
	Do(method, path string, in, out any) error
}

// Source implements ui.AppSource.
type Source struct {
	Client Client
	// Procs returns the paths of the running programs; nil: Running().
	Procs func() []string
	// Installed returns the Start menu programs; nil: StartMenu().
	Installed func() []StartMenuProgram
	// TTL keeps the process list for a while (listing is not free).
	TTL time.Duration
	// Self is shunt-desktop.exe: launchers start their program through it.
	Self string
	// LauncherDir holds launchers.json, MenuDir the launchers' shortcuts;
	// "": %APPDATA%\Shunt and the user's Start menu.
	LauncherDir, MenuDir string
	// Shortcut writes a .lnk; nil: MakeShortcut.
	Shortcut func(Shortcut) error

	cached  []string
	cachedT time.Time

	inst  []StartMenuProgram
	instT time.Time
}

func (s *Source) installed() []StartMenuProgram {
	if s.inst != nil && time.Since(s.instT) < time.Minute {
		return s.inst
	}
	f := s.Installed
	if f == nil {
		f = StartMenu
	}
	s.inst, s.instT = f(), time.Now()
	if s.inst == nil {
		s.inst = []StartMenuProgram{}
	}
	return s.inst
}

func idOf(path string) string {
	return strings.ToLower(filepath.Base(strings.ReplaceAll(path, `\`, "/")))
}

func isUninstaller(name, path string) bool {
	n := strings.ToLower(name + " " + filepath.Base(strings.ReplaceAll(path, `\`, "/")))
	return strings.Contains(n, "uninstall") || strings.Contains(n, "deinstall")
}

func (s *Source) procs() []string {
	ttl := s.TTL
	if ttl == 0 {
		ttl = 10 * time.Second
	}
	if s.cached != nil && time.Since(s.cachedT) < ttl {
		return s.cached
	}
	f := s.Procs
	if f == nil {
		f = Running
	}
	s.cached, s.cachedT = f(), time.Now()
	return s.cached
}

// system paths: nobody routes these programs one by one
func isSystem(path string) bool {
	p := strings.ToLower(path)
	return strings.Contains(p, `\windows\system32\`) || strings.Contains(p, `\windows\syswow64\`) ||
		strings.Contains(p, `\windows\winsxs\`) || strings.Contains(p, `\windows\systemapps\`) ||
		strings.HasPrefix(p, `c:\windows\`) && !strings.Contains(p[len(`c:\windows\`):], `\`) && p != `c:\windows\explorer.exe`
}

// Name turns "firefox.exe" into "Firefox".
func Name(id string) string {
	n := strings.TrimSuffix(id, ".exe")
	if n == "" {
		return id
	}
	return strings.ToUpper(n[:1]) + n[1:]
}

func ruleID(r config.Rule) (string, bool) {
	if !strings.HasPrefix(r.Name, RulePrefix) || len(r.App) != 1 {
		return "", false
	}
	return strings.ToLower(r.App[0]), true
}

// List returns the programs, then the launchers.
func (s *Source) List() ([]desktop.Entry, error) {
	list, err := s.programs()
	if err != nil {
		return nil, err
	}
	return append(list, s.launcherEntries()...), nil
}

// programs returns the programs (sorted by ID) with the route of their rule.
func (s *Source) programs() ([]desktop.Entry, error) {
	var v api.ConfigView
	if err := s.Client.Do("GET", "/v1/config", nil, &v); err != nil {
		return nil, err
	}
	routes := map[string]string{}
	if v.Config != nil {
		for _, r := range v.Config.Rules {
			if id, ok := ruleID(r); ok {
				routes[id] = r.Route
			}
		}
	}
	byID := map[string]desktop.Entry{}
	// installed programs first: they carry the proper name ("Mozilla Firefox")
	for _, p := range s.installed() {
		if isSystem(p.Path) || isUninstaller(p.Name, p.Path) {
			continue
		}
		if id := idOf(p.Path); id != "" {
			if _, ok := byID[id]; !ok {
				byID[id] = desktop.Entry{ID: id, Name: p.Name, Exec: p.Path, Online: true}
			}
		}
	}
	for _, p := range s.procs() {
		if isSystem(p) {
			continue
		}
		id := idOf(p)
		if _, ok := byID[id]; !ok {
			byID[id] = desktop.Entry{ID: id, Name: Name(id), Exec: p, Online: true}
		}
	}
	for id := range routes {
		if _, ok := byID[id]; !ok {
			byID[id] = desktop.Entry{ID: id, Name: Name(id), Online: true}
		}
	}
	list := make([]desktop.Entry, 0, len(byID))
	for id, e := range byID {
		e.Route = routes[id]
		e.Chromium = desktop.ChromiumBrowserOfExe(e.Exec)
		list = append(list, e)
	}
	slices.SortFunc(list, func(a, b desktop.Entry) int { return strings.Compare(a.ID, b.ID) })
	return list, nil
}

// SetRoute sets (or, with "", removes) the rule of a program, or the route
// of a launcher ("" removes the launcher).
func (s *Source) SetRoute(id, route string) error {
	if found, err := s.setLauncher(id, route); found || err != nil {
		return err
	}
	id = strings.ToLower(strings.TrimSpace(id))
	if id == "" || strings.ContainsAny(id, `\/:*?"<>|`) {
		return errors.New("invalid program name")
	}
	var v api.ConfigView
	if err := s.Client.Do("GET", "/v1/config", nil, &v); err != nil {
		return err
	}
	if v.Config == nil {
		return errors.New("no config")
	}
	c := v.Config
	var rules []config.Rule
	found := false
	for _, r := range c.Rules {
		if rid, ok := ruleID(r); ok && rid == id {
			found = true
			if route == "" {
				continue // removed
			}
			r.Route = route
		}
		rules = append(rules, r)
	}
	if !found && route != "" {
		// first in the list: nothing else should win against an explicit choice
		rules = append([]config.Rule{{Name: RulePrefix + id, App: []string{id}, Route: route}}, rules...)
	}
	c.Rules = rules
	var res api.CheckResult
	if err := s.Client.Do("PUT", "/v1/config", api.ConfigSave{Config: c, Version: v.Version}, &res); err != nil {
		return fmt.Errorf("%w", err)
	}
	return nil
}
