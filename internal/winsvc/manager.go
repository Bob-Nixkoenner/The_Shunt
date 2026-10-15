package winsvc

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/Bob-Nixkoenner/the_shunt/internal/api"
	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/Bob-Nixkoenner/the_shunt/internal/ovpnconf"
	"github.com/Bob-Nixkoenner/the_shunt/internal/splitstack"
	"github.com/Bob-Nixkoenner/the_shunt/internal/wgconf"
)

// Manager owns shunt.toml and the tunnel files in Dir, checks and applies
// changes from the API. Rules of the game (as on Linux):
//   - nothing is written that does not pass the checks
//   - tunnel files must live in Dir\tunnels
//   - the previous file is kept as shunt.toml.bak
//   - a changed tunnel set needs a new engine: Restart is called, the new
//     config is already on disk then; rule changes apply live (SetRules)
type Manager struct {
	Dir string
	// StatsPath is added to the engine config (traffic totals).
	StatsPath string
	// Secure is called on the tunnel folder after creating it (Windows:
	// only SYSTEM and Administrators may read private keys). May be nil.
	Secure func(dir string)
	// SetRules applies rule changes to the running engine, Restart asks
	// for a restart (tunnels changed).
	SetRules func(js string) error
	Restart  func()
	// OnConfig is called with every config that takes effect (after Load,
	// Save and Reload): the platform applies settings the engine does not
	// know, like the kill switch. May be nil.
	OnConfig func(c *config.Config)

	mu      sync.Mutex
	saveMu  sync.Mutex
	cfg     *config.Config
	running string // fingerprint of the tunnels the engine runs with
}

const defaultConfig = "# The Shunt for Windows\n[daemon]\ndefault_route = \"direct\"\n"

func (m *Manager) path() string      { return filepath.Join(m.Dir, "shunt.toml") }
func (m *Manager) tunnelDir() string { return filepath.Join(m.Dir, "tunnels") }

func (m *Manager) abs(p string) string {
	if !filepath.IsAbs(p) {
		p = filepath.Join(m.Dir, p)
	}
	return filepath.Clean(p)
}

func (m *Manager) readFile(p string) ([]byte, error) { return os.ReadFile(m.abs(p)) }

// Load reads shunt.toml (creating a safe default: everything direct) and
// returns the engine config for it.
func (m *Manager) Load() (js string, warnings []string, err error) {
	if err := os.MkdirAll(m.Dir, 0o755); err != nil {
		return "", nil, err
	}
	b, err := os.ReadFile(m.path())
	if errors.Is(err, os.ErrNotExist) {
		b = []byte(defaultConfig)
		err = writeAtomic(m.path(), b, 0o644)
	}
	if err != nil {
		return "", nil, err
	}
	c, js, warnings, err := m.build(b)
	if err != nil {
		return "", nil, err
	}
	m.mu.Lock()
	m.cfg, m.running = c, fingerprint(js)
	m.mu.Unlock()
	m.changed(c)
	return js, warnings, nil
}

func (m *Manager) changed(c *config.Config) {
	if m.OnConfig != nil {
		m.OnConfig(c)
	}
}

// Reload re-reads shunt.toml after a change by hand (POST /v1/reload).
func (m *Manager) Reload() error {
	m.saveMu.Lock()
	defer m.saveMu.Unlock()
	raw, err := os.ReadFile(m.path())
	if err != nil {
		return err
	}
	c, js, _, err := m.build(raw)
	if err != nil {
		return err
	}
	m.mu.Lock()
	restart := fingerprint(js) != m.running
	m.mu.Unlock()
	if restart && m.Restart != nil {
		m.Restart()
		return nil
	}
	if m.SetRules != nil {
		if err := m.SetRules(js); err != nil {
			return err
		}
	}
	m.mu.Lock()
	m.cfg = c
	m.mu.Unlock()
	m.changed(c)
	return nil
}

// build parses raw and translates it; nothing is stored.
func (m *Manager) build(raw []byte) (*config.Config, string, []string, error) {
	c, err := config.Parse(string(raw))
	if err != nil {
		return nil, "", nil, err
	}
	for name, t := range c.Tunnels {
		for _, f := range []string{t.Config, t.Auth} {
			if f != "" && !strings.HasPrefix(m.abs(f), m.tunnelDir()+string(filepath.Separator)) {
				return nil, "", nil, fmt.Errorf("tunnel %q: config and auth files must be in %s", name, m.tunnelDir())
			}
		}
	}
	js, warn, err := Translate(c, m.readFile)
	if err != nil {
		return nil, "", nil, err
	}
	js = m.withStats(js)
	if err := splitstack.CheckConfig(js); err != nil {
		return nil, "", nil, err
	}
	return c, js, warn, nil
}

func (m *Manager) withStats(js string) string {
	if m.StatsPath == "" {
		return js
	}
	var o map[string]any
	if json.Unmarshal([]byte(js), &o) != nil {
		return js
	}
	o["stats_path"] = m.StatsPath
	b, _ := json.Marshal(o)
	return string(b)
}

// fingerprint covers what the engine cannot change while running.
func fingerprint(js string) string {
	var o struct {
		Tunnels json.RawMessage `json:"tunnels"`
	}
	_ = json.Unmarshal([]byte(js), &o)
	return fmt.Sprintf("%x", sha256.Sum256(o.Tunnels))
}

// Summary gives the status the default route and the app rules.
func (m *Manager) Summary() (string, map[string]string) {
	m.mu.Lock()
	c := m.cfg
	m.mu.Unlock()
	if c == nil {
		return "block", nil
	}
	apps := map[string]string{}
	for _, r := range c.Rules {
		if r.Route == "" || len(r.CIDR)+len(r.Port)+len(r.Domain) > 0 {
			continue
		}
		for _, id := range appIDs(r.App, func(string) {}) {
			if _, ok := apps[id]; !ok {
				apps[id] = r.Route
			}
		}
	}
	return c.Daemon.DefaultRoute, apps
}

func fileVersion(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }

// View returns the config for the UI; private keys never leave.
func (m *Manager) View() (api.ConfigView, error) {
	raw, err := os.ReadFile(m.path())
	if err != nil {
		return api.ConfigView{}, err
	}
	m.mu.Lock()
	c := m.cfg
	m.mu.Unlock()
	if c == nil {
		return api.ConfigView{}, errors.New("config not loaded")
	}
	v := api.ConfigView{Raw: string(raw), Version: fileVersion(raw), Config: c, DNSFilter: c.Filter(), Tunnels: []api.TunnelConfInfo{}}
	for name, t := range c.Tunnels {
		b, err := m.readFile(t.Config)
		if err != nil {
			continue
		}
		ti := api.TunnelConfInfo{Name: name, Type: "wireguard"}
		if t.IsOpenVPN() {
			ti.Type, ti.AllowedIPs = "openvpn", []string{"0.0.0.0/0", "::/0"}
			if oc, err := ovpnconf.Parse(string(b), ""); err == nil && len(oc.Remotes) > 0 {
				ti.Endpoint = oc.Remotes[0]
			}
		} else if wc, err := wgconf.Parse(strings.NewReader(string(b))); err == nil {
			ti.DNS = wc.DNS
			for _, a := range wc.Addresses {
				ti.Addresses = append(ti.Addresses, a.String())
			}
			for _, p := range wc.Peers {
				if ti.Endpoint == "" {
					ti.Endpoint = p.Endpoint
				}
				for _, a := range p.AllowedIPs {
					ti.AllowedIPs = append(ti.AllowedIPs, a.String())
				}
			}
		}
		v.Tunnels = append(v.Tunnels, ti)
	}
	slices.SortFunc(v.Tunnels, func(a, b api.TunnelConfInfo) int { return strings.Compare(a.Name, b.Name) })
	return v, nil
}

// RawOf returns the TOML text of a save request.
func (m *Manager) RawOf(req api.ConfigSave) ([]byte, error) {
	if req.Config != nil {
		return req.Config.Encode()
	}
	if req.Raw == "" {
		return nil, errors.New("empty config")
	}
	return []byte(req.Raw), nil
}

// Check validates raw config text without applying it.
func (m *Manager) Check(raw []byte) ([]string, error) {
	_, _, warn, err := m.build(raw)
	return warn, err
}

// ErrConflict: the file changed since the editor loaded it.
var ErrConflict = errors.New("the config file was changed meanwhile (by hand or in another window); nothing was saved – reload and make your change again")

// Save validates, writes and applies raw config text. expect is the version
// the change is based on ("" = no check).
func (m *Manager) Save(raw []byte, expect string) ([]string, error) {
	m.saveMu.Lock()
	defer m.saveMu.Unlock()
	old, err := os.ReadFile(m.path())
	if err != nil {
		return nil, err
	}
	if expect != "" && expect != fileVersion(old) {
		return nil, ErrConflict
	}
	c, js, warn, err := m.build(raw)
	if err != nil {
		return nil, err
	}
	if err := writeAtomic(m.path()+".bak", old, 0o644); err != nil {
		return nil, err
	}
	if err := writeAtomic(m.path(), raw, 0o644); err != nil {
		return nil, err
	}
	m.mu.Lock()
	restart := fingerprint(js) != m.running
	m.mu.Unlock()
	if restart {
		m.mu.Lock()
		m.cfg = c
		m.mu.Unlock()
		m.changed(c)
		if m.Restart != nil {
			m.Restart()
		}
		return append(warn, "tunnels changed: the service restarts to apply them"), nil
	}
	if m.SetRules != nil {
		if err := m.SetRules(js); err != nil {
			_ = writeAtomic(m.path(), old, 0o644)
			return nil, fmt.Errorf("could not apply (previous config restored): %w", err)
		}
	}
	m.mu.Lock()
	m.cfg = c
	m.mu.Unlock()
	m.changed(c)
	return warn, nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	_ = os.Remove(path) // Windows: rename onto an existing file fails on some setups
	return os.Rename(tmp, path)
}

var tunnelNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,9}$`)

// ImportTunnel stores a wg-quick file or an OpenVPN client config and adds
// the tunnel to shunt.toml (appended, comments survive).
func (m *Manager) ImportTunnel(req api.TunnelImport) ([]string, error) {
	if !tunnelNameRe.MatchString(req.Name) {
		return nil, errors.New("name: 1-10 characters a-z 0-9 -, starting with a letter or digit")
	}
	var warn []string
	ext, driver, needsAuth := ".conf", "", false
	if strings.Contains(req.Conf, "[Interface]") {
		wc, err := wgconf.Parse(strings.NewReader(req.Conf))
		if err != nil {
			return nil, fmt.Errorf("WireGuard config: %w", err)
		}
		if len(wc.Ignored) > 0 {
			warn = append(warn, "ignored in the WireGuard file: "+strings.Join(wc.Ignored, ", "))
		}
	} else {
		clean, removed := ovpnconf.Sanitize(req.Conf)
		if len(removed) > 0 {
			req.Conf = clean
			warn = append(warn, "not used from the OpenVPN file (Shunt does routing and DNS itself, no scripts): "+strings.Join(removed, ", "))
		}
		oc, err := ovpnconf.Parse(req.Conf, "")
		if err != nil {
			return nil, fmt.Errorf("OpenVPN config: %w", err)
		}
		ext, driver, needsAuth = ".ovpn", "openvpn", oc.NeedsAuth
		if needsAuth && (req.Username == "" || req.Password == "") {
			return nil, errors.New("this OpenVPN server wants a username and password")
		}
	}
	if strings.ContainsAny(req.Username+req.Password, "\n\r") {
		return nil, errors.New("username/password must not contain line breaks")
	}
	m.mu.Lock()
	_, exists := m.cfg.Tunnels[req.Name]
	m.mu.Unlock()
	if exists {
		return nil, fmt.Errorf("a tunnel %q exists already", req.Name)
	}
	if err := os.MkdirAll(m.tunnelDir(), 0o700); err != nil {
		return nil, err
	}
	if m.Secure != nil {
		m.Secure(m.tunnelDir())
	}
	file := filepath.Join(m.tunnelDir(), req.Name+ext)
	auth := filepath.Join(m.tunnelDir(), req.Name+".auth")
	for _, f := range []string{file, auth, filepath.Join(m.tunnelDir(), req.Name+".conf"), filepath.Join(m.tunnelDir(), req.Name+".ovpn")} {
		_ = os.Remove(f) // left over from a tunnel removed by hand
	}
	if err := writeAtomic(file, []byte(req.Conf), 0o600); err != nil {
		return nil, err
	}
	block := fmt.Sprintf("\n[tunnel.%s]\nconfig = %q\n", req.Name, "tunnels/"+req.Name+ext)
	if driver != "" {
		block += fmt.Sprintf("driver = %q\n", driver)
	}
	if needsAuth {
		if err := writeAtomic(auth, []byte(req.Username+"\n"+req.Password+"\n"), 0o600); err != nil {
			os.Remove(file)
			return nil, err
		}
		block += fmt.Sprintf("auth = %q\n", "tunnels/"+req.Name+".auth")
	}
	if req.DNS != "" {
		block += fmt.Sprintf("dns = %q\n", req.DNS)
	}
	if req.Via != "" {
		block += fmt.Sprintf("via = %q\n", req.Via)
	}
	raw, err := os.ReadFile(m.path())
	if err != nil {
		os.Remove(file)
		os.Remove(auth)
		return nil, err
	}
	w, err := m.Save([]byte(strings.TrimRight(string(raw), "\n")+"\n"+block), "")
	if err != nil {
		os.Remove(file)
		os.Remove(auth)
		return nil, err
	}
	return append(w, warn...), nil
}

// DeleteTunnel removes a tunnel that nothing uses anymore.
func (m *Manager) DeleteTunnel(name string) error {
	m.mu.Lock()
	if m.cfg == nil {
		m.mu.Unlock()
		return errors.New("config not loaded")
	}
	cfg := *m.cfg
	t, ok := cfg.Tunnels[name]
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("no tunnel %q", name)
	}
	route := "tunnel:" + name
	if cfg.Daemon.DefaultRoute == route {
		return fmt.Errorf("tunnel %q is the default route; change that first", name)
	}
	for i, r := range cfg.Rules {
		if r.Route == route {
			return fmt.Errorf("rule %d (%s) uses tunnel %q; change or delete it first", i+1, r.Name, name)
		}
	}
	for _, n := range cfg.Networks {
		if n.DefaultRoute == route {
			return fmt.Errorf("network %q uses tunnel %q; change or delete it first", n.Name, name)
		}
	}
	for n, tt := range cfg.Tunnels {
		if tt.Via == route || tt.Via == name {
			return fmt.Errorf("tunnel %q runs through %q; change or delete it first", n, name)
		}
	}
	tunnels := map[string]config.Tunnel{}
	for n, tt := range cfg.Tunnels {
		if n != name {
			tunnels[n] = tt
		}
	}
	cfg.Tunnels = tunnels
	raw, err := cfg.Encode()
	if err != nil {
		return err
	}
	if _, err := m.Save(raw, ""); err != nil {
		return err
	}
	for _, f := range []string{t.Config, t.Auth} {
		if p := m.abs(f); f != "" && strings.HasPrefix(p, m.tunnelDir()+string(filepath.Separator)) {
			_ = os.Remove(p)
		}
	}
	return nil
}
