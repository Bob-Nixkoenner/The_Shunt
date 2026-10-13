// Package firewall is The Shunt's app firewall: a program of the desktop
// session without a rule is held in a waiting group (no network, nothing
// leaks) until the user picks a route for it – or, in "ask" mode, until a
// timeout gives it the default route.
//
// How a held program is noticed: its cgroup gets an nft rule that logs its
// first packets to an NFLOG group with the prefix "ask:<id> " and rejects
// them (see nft.AskRules). Programs that never use the network are held
// silently and never asked about.
package firewall

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/appwatch"
	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/Bob-Nixkoenner/the_shunt/internal/engine"
	"github.com/Bob-Nixkoenner/the_shunt/internal/nft"
)

// CGroups is what the firewall needs from the cgroup manager.
type CGroups interface {
	Ensure(rel string) error
	Move(rel string, pid int) error
	Procs(rel string) ([]int, error)
	Remove(rel string) error
}

// Pending is a held program that tried to reach the network.
type Pending struct {
	ID       string    `json:"id"`
	Key      string    `json:"key"` // exe path, "flatpak:<id>" or "name:<comm>"
	Name     string    `json:"name"`
	UID      int       `json:"uid"`
	Asked    time.Time `json:"asked"`
	Deadline time.Time `json:"deadline,omitempty"` // ask mode: default route then
	Procs    int       `json:"procs"`
}

// Remembered is a stored decision.
type Remembered struct {
	Key   string    `json:"key"`
	Name  string    `json:"name"`
	Route string    `json:"route"`
	Since time.Time `json:"since"`
}

// Settings come from the config and the plan; Configure applies them.
type Settings struct {
	Mode        string            // config.FirewallOff / Ask / Block
	Timeout     time.Duration     // ask mode
	AskTerminal bool              // hold programs started from a terminal too
	Root        string            // Shunt's cgroup root
	Groups      map[string]string // route name -> cgroup path of its via-group
}

type entry struct {
	Pending
	path string
}

// Manager holds and releases programs.
type Manager struct {
	Log   *slog.Logger
	CG    CGroups
	Apply func(script string) error // nft
	Store string                    // remembered decisions (JSON)
	// Changed is called (without locks held) when the pending list changes.
	Changed func()
	// Placed is told about every process the firewall moves into a route
	// (the app watcher keeps it there, see appwatch.Place).
	Placed func(pid int, path string)

	mu         sync.Mutex
	set        Settings
	byKey      map[string]*entry
	byID       map[string]*entry
	session    map[string]string // key -> route, decided for this run
	remembered map[string]Remembered
	next       int
}

func (m *Manager) init() {
	if m.byKey == nil {
		m.byKey, m.byID, m.session = map[string]*entry{}, map[string]*entry{}, map[string]string{}
		m.remembered = map[string]Remembered{}
		m.load()
	}
}

func (m *Manager) freePath() string         { return path.Join(m.set.Root, "apps", "free") }
func (m *Manager) askPath(id string) string { return askPathIn(m.set.Root, id) }

func askPathIn(root, id string) string { return path.Join(root, "apps", "ask", id) }

// Configure applies new settings and (re)installs the nft rules of the
// waiting groups – call it after every ruleset reload. Switching the
// firewall off releases every held program.
func (m *Manager) Configure(s Settings) error {
	m.mu.Lock()
	m.init()
	m.set = s
	if err := m.CG.Ensure(m.freePath()); err != nil {
		m.mu.Unlock()
		return err
	}
	var released bool
	if s.Mode == config.FirewallOff || s.Mode == "" {
		for _, e := range m.byID {
			m.release(e, m.freePath())
			released = true
		}
	}
	for _, e := range m.byID { // a new plan may have moved the root
		e.path = m.askPath(e.ID)
	}
	err := m.applyRules()
	m.mu.Unlock()
	if released {
		m.changed()
	}
	return err
}

func (m *Manager) changed() {
	if m.Changed != nil {
		m.Changed()
	}
}

// desktop components and helpers that are never held: they are part of
// the session, not "apps", and asking about them helps nobody.
var neverAsk = regexp.MustCompile(`^(cosmic-|gnome-|gsd-|xfce4-|xfwm4|xfdesktop|xfsettingsd|plasmashell|kwin|ksmserver|kded|pipewire|wireplumber|pulseaudio|dbus|gvfs|at-spi|ibus|fcitx|xdg-|polkit|evolution-|tracker|nm-applet|blueman|shunt|systemd|Xwayland|Xorg|gdm|sddm|lightdm|bwrap$|flatpak-|xdg-dbus-proxy|snapd|update-notifier|gjs|tumblerd|light-locker|xiccd|udisks)`)

var sessionScope = regexp.MustCompile(`^user\.slice/user-\d+\.slice/(session-\d+\.scope|user@\d+\.service/app\.slice/)`)

// Unknown is the app watcher's callback for programs without a rule.
func (m *Manager) Unknown(pid int, p appwatch.Proc) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.init()
	if m.set.Mode != config.FirewallAsk && m.set.Mode != config.FirewallBlock {
		return
	}
	// held already: a waiting wrapper exec'd the real program, which gets
	// its own decision
	held := strings.HasPrefix(p.Cgroup, path.Join(m.set.Root, "apps", "ask")+"/")
	if !held && (!sessionScope.MatchString(p.Cgroup) || neverAsk.MatchString(p.Comm) || (p.TTY && !m.set.AskTerminal)) {
		return
	}
	key, name := keyOf(p)
	if route, ok := m.session[key]; ok {
		m.moveTo(route, pid, name)
		return
	}
	if r, ok := m.remembered[key]; ok {
		if m.moveTo(r.Route, pid, name) {
			return
		}
	}
	e := m.byKey[key]
	if e != nil && p.Cgroup == e.path {
		return // already there
	}
	if e == nil {
		m.next++
		id := fmt.Sprintf("p%d", m.next)
		e = &entry{Pending: Pending{ID: id, Key: key, Name: name, UID: p.UID}, path: m.askPath(id)}
		if err := m.CG.Ensure(e.path); err != nil {
			m.Log.Warn("app firewall: cannot create waiting group", "err", err)
			return
		}
		m.byKey[key], m.byID[id] = e, e
		if err := m.applyRules(); err != nil {
			m.Log.Warn("app firewall: rules", "err", err)
		}
	}
	if err := m.CG.Move(e.path, pid); err == nil {
		m.Log.Debug("app firewall: holding", "app", name, "pid", pid)
	}
}

// moveTo puts pid into route's via-group; false if the route is gone.
func (m *Manager) moveTo(route string, pid int, name string) bool {
	g := m.groupFor(route)
	if g == "" {
		return false
	}
	if m.CG.Move(g, pid) == nil && m.Placed != nil {
		m.Placed(pid, g)
	}
	return true
}

func (m *Manager) groupFor(route string) string {
	if route == "" {
		return m.freePath()
	}
	return m.set.Groups[route]
}

// keyOf identifies a program: its binary (or flatpak id), so every start
// of it shares one decision.
func keyOf(p appwatch.Proc) (key, name string) {
	if i := strings.Index(p.Cgroup, "app-flatpak-"); i >= 0 {
		id := p.Cgroup[i+len("app-flatpak-"):]
		if j := strings.LastIndex(id, "-"); j > 0 {
			id = id[:j]
		}
		return "flatpak:" + id, id
	}
	if p.Exe != "" {
		return p.Exe, filepath.Base(p.Exe)
	}
	return "name:" + p.Comm, p.Comm
}

// Seen is the NFLOG callback: the waiting group id tried to send.
func (m *Manager) Seen(id string, uid int) {
	m.mu.Lock()
	e := m.byID[id]
	first := e != nil && e.Asked.IsZero()
	if first {
		e.Asked = time.Now()
		if uid >= 0 {
			e.UID = uid
		}
		if m.set.Mode == config.FirewallAsk {
			e.Deadline = e.Asked.Add(m.set.Timeout)
		}
		m.Log.Info("app firewall: program wants network", "app", e.Name, "key", e.Key, "mode", m.set.Mode)
	}
	m.mu.Unlock()
	if first {
		m.changed()
	}
}

// Tick handles timeouts and cleans up; call it about once a second.
func (m *Manager) Tick(now time.Time) {
	m.mu.Lock()
	var changed bool
	for _, e := range m.byID {
		procs, _ := m.CG.Procs(e.path)
		switch {
		case !e.Deadline.IsZero() && now.After(e.Deadline):
			m.Log.Info("app firewall: no answer, default route", "app", e.Name)
			m.release(e, m.freePath())
			changed = true
		case len(procs) == 0 && (e.Asked.IsZero() || now.Sub(e.Asked) > 5*time.Second):
			// the program is gone (or exec'd another one, which got its
			// own group); forget it – it is asked again next time
			m.drop(e)
			changed = changed || !e.Asked.IsZero()
		}
	}
	if changed {
		_ = m.applyRules()
	}
	m.mu.Unlock()
	if changed {
		m.changed()
	}
}

// List returns the programs waiting for an answer.
func (m *Manager) List() []Pending {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []Pending{}
	for _, e := range m.byID {
		if e.Asked.IsZero() {
			continue
		}
		p := e.Pending
		procs, _ := m.CG.Procs(e.path)
		if p.Procs = len(procs); p.Procs == 0 {
			continue // gone, or became another program
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Asked.Before(out[j].Asked) })
	return out
}

// ErrUnknown: no such waiting program.
var ErrUnknown = errors.New("no such waiting program (already decided?)")

// Decide sends a waiting program (all its processes) into route ("" = the
// default route, following it when it changes) and remembers the choice
// for this run, or for good.
func (m *Manager) Decide(id, route string, remember bool) error {
	m.mu.Lock()
	m.init()
	e := m.byID[id]
	if e == nil {
		m.mu.Unlock()
		return ErrUnknown
	}
	g := m.groupFor(route)
	if g == "" {
		m.mu.Unlock()
		return fmt.Errorf("unknown route %q", route)
	}
	m.release(e, g)
	m.session[e.Key] = route
	var err error
	if remember {
		m.remembered[e.Key] = Remembered{Key: e.Key, Name: e.Name, Route: route, Since: time.Now()}
		err = m.save()
	}
	err = errors.Join(err, m.applyRules())
	m.Log.Info("app firewall: decided", "app", e.Name, "route", route, "remember", remember)
	m.mu.Unlock()
	m.changed()
	return err
}

// release moves every process of e to group g and forgets e. Caller holds m.mu.
func (m *Manager) release(e *entry, g string) {
	procs, _ := m.CG.Procs(e.path)
	for _, pid := range procs {
		if m.CG.Move(g, pid) == nil && m.Placed != nil {
			m.Placed(pid, g)
		}
	}
	m.drop(e)
}

func (m *Manager) drop(e *entry) {
	delete(m.byID, e.ID)
	delete(m.byKey, e.Key)
	_ = m.CG.Remove(e.path)
}

// Remembered lists the stored decisions.
func (m *Manager) Remembered() []Remembered {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.init()
	out := []Remembered{}
	for _, r := range m.remembered {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Forget removes a stored decision (the program is asked again next start).
func (m *Manager) Forget(key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.init()
	if _, ok := m.remembered[key]; !ok {
		return fmt.Errorf("no stored decision for %q", key)
	}
	delete(m.remembered, key)
	delete(m.session, key)
	return m.save()
}

// RulesFor returns the nft rules of the waiting groups for cgroup root
// root. A ruleset reload replaces the table and with it these rules: append
// them to the new ruleset so held programs never get out in between.
func (m *Manager) RulesFor(root string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.rules(root)
}

func (m *Manager) rules(root string) (string, error) {
	groups := map[string]engine.Group{}
	for id, e := range m.byID {
		groups[id] = engine.Group{Name: "ask:" + e.Name, Path: askPathIn(root, id)}
	}
	return nft.AskRules(groups)
}

// applyRules installs the nft rules of all waiting groups. Caller holds m.mu.
func (m *Manager) applyRules() error {
	if m.Apply == nil {
		return nil
	}
	s, err := m.rules(m.set.Root)
	if err != nil {
		return err
	}
	return m.Apply(s)
}

func (m *Manager) load() {
	if m.Store == "" {
		return
	}
	b, err := os.ReadFile(m.Store)
	if err != nil {
		return
	}
	var list []Remembered
	if err := json.Unmarshal(b, &list); err != nil {
		m.Log.Warn("app firewall: cannot read stored decisions", "file", m.Store, "err", err)
		return
	}
	for _, r := range list {
		m.remembered[r.Key] = r
	}
}

func (m *Manager) save() error {
	if m.Store == "" {
		return nil
	}
	list := make([]Remembered, 0, len(m.remembered))
	for _, r := range m.remembered {
		list = append(list, r)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Key < list[j].Key })
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := m.Store + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, m.Store)
}
