package daemon

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/Bob-Nixkoenner/the_shunt/internal/api"
	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/Bob-Nixkoenner/the_shunt/internal/ovpnconf"
	"github.com/Bob-Nixkoenner/the_shunt/internal/wgconf"
)

// Config editing through the API (UI). Rules of the game:
//   - nothing is written that does not pass the same checks as `shuntd check`
//   - the [daemon] section (socket, group, cgroup) only changes in the file
//   - tunnel files must live in <config dir>/tunnels: the API can never make
//     the root daemon read an arbitrary file
//   - the previous file is kept as shunt.toml.bak; if the new config cannot
//     be applied, the old one is restored and applied again

func (d *Daemon) tunnelDir() string { return filepath.Join(filepath.Dir(d.ConfigPath), "tunnels") }

// configView returns the config for the UI; private keys never leave.
func (d *Daemon) configView() (api.ConfigView, error) {
	raw, err := os.ReadFile(d.ConfigPath)
	if err != nil {
		return api.ConfigView{}, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	v := api.ConfigView{Raw: string(raw), Version: fileVersion(raw), Config: d.cfg}
	for name, wc := range d.prep.Confs {
		ti := api.TunnelConfInfo{Name: name, Type: "wireguard", DNS: wc.DNS}
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
		v.Tunnels = append(v.Tunnels, ti)
	}
	for name, oc := range d.prep.OVPN {
		ti := api.TunnelConfInfo{Name: name, Type: "openvpn", AllowedIPs: []string{"0.0.0.0/0", "::/0"}}
		if len(oc.Remotes) > 0 {
			ti.Endpoint = oc.Remotes[0]
		}
		v.Tunnels = append(v.Tunnels, ti)
	}
	slices.SortFunc(v.Tunnels, func(a, b api.TunnelConfInfo) int { return strings.Compare(a.Name, b.Name) })
	return v, nil
}

// checkCandidate validates raw config text without applying it.
func (d *Daemon) checkCandidate(raw []byte) (*Prepared, error) {
	c, err := config.Parse(string(raw))
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	cur, root := d.cfg.Daemon, d.plan.CgroupRoot
	oldPaths := map[string]bool{}
	for _, t := range d.cfg.Tunnels {
		oldPaths[d.absConf(t.Config)] = true
		if t.Auth != "" {
			oldPaths[d.absConf(t.Auth)] = true
		}
	}
	d.mu.Unlock()
	if c.Daemon.Socket != cur.Socket || c.Daemon.SocketGroup != cur.SocketGroup || c.Daemon.CgroupRoot != cur.CgroupRoot || c.Daemon.APIAuth != cur.APIAuth {
		return nil, errors.New("the [daemon] socket/socket_group/cgroup_root/api_auth settings can only be changed in the file itself")
	}
	for name, t := range c.Tunnels {
		// The auth file is sent to the VPN server: same rule as configs.
		for _, f := range []string{t.Config, t.Auth} {
			if f == "" {
				continue
			}
			p := d.absConf(f)
			if !oldPaths[p] && !strings.HasPrefix(p, d.tunnelDir()+string(filepath.Separator)) {
				return nil, fmt.Errorf("tunnel %q: config and auth files must be in %s", name, d.tunnelDir())
			}
		}
	}
	tmp := filepath.Join(filepath.Dir(d.ConfigPath), ".shunt.toml.candidate")
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return nil, err
	}
	defer os.Remove(tmp)
	d.mu.Lock()
	ni, ls := d.netInfo, d.links
	d.mu.Unlock()
	return PrepareOn(tmp, root, Env{Net: &ni, Links: ls, Backend: d.Backend})
}

func (d *Daemon) absConf(p string) string {
	if !filepath.IsAbs(p) {
		p = filepath.Join(filepath.Dir(d.ConfigPath), p)
	}
	return filepath.Clean(p)
}

func fileVersion(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }

// errConflict: the file changed since the editor loaded it.
var errConflict = errors.New("the config file was changed meanwhile (by hand or in another window); nothing was saved – reload and make your change again")

// saveConfig validates, writes and applies raw config text. expect is the
// version the change is based on ("" = no check).
func (d *Daemon) saveConfig(raw []byte, expect string) (*Prepared, error) {
	d.saveMu.Lock()
	defer d.saveMu.Unlock()
	old, err := os.ReadFile(d.ConfigPath)
	if err != nil {
		return nil, err
	}
	if expect != "" && expect != fileVersion(old) {
		return nil, errConflict
	}
	p, err := d.checkCandidate(raw)
	if err != nil {
		return nil, err
	}
	if err := writeAtomic(d.ConfigPath+".bak", old, 0o644); err != nil {
		return nil, err
	}
	if err := writeAtomic(d.ConfigPath, raw, 0o644); err != nil {
		return nil, err
	}
	d.mu.Lock()
	root := d.plan.CgroupRoot
	d.mu.Unlock()
	if err := d.reload(root); err != nil {
		d.Log.Error("new config could not be applied, restoring the previous one", "err", err)
		_ = writeAtomic(d.ConfigPath, old, 0o644)
		if err2 := d.reload(root); err2 != nil {
			d.Log.Error("restoring the previous config failed too", "err", err2)
		}
		return nil, fmt.Errorf("could not apply (previous config restored): %w", err)
	}
	d.Log.Info("config saved via API", "path", d.ConfigPath)
	return p, nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

var tunnelNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,9}$`)

// importTunnel stores a wg-quick file or an OpenVPN client config and adds
// the tunnel to the config. The table is appended to the raw text, so
// comments in the file survive.
func (d *Daemon) importTunnel(req api.TunnelImport) (*Prepared, error) {
	if !tunnelNameRe.MatchString(req.Name) {
		return nil, errors.New("name: 1-10 characters a-z 0-9 -, starting with a letter or digit")
	}
	var warn []string
	ext, driver := ".conf", ""
	needsAuth := false
	if strings.Contains(req.Conf, "[Interface]") {
		wc, err := wgconf.Parse(strings.NewReader(req.Conf))
		if err != nil {
			return nil, fmt.Errorf("WireGuard config: %w", err)
		}
		if len(wc.Ignored) > 0 {
			warn = append(warn, "ignored in the WireGuard file: "+strings.Join(wc.Ignored, ", "))
		}
	} else {
		// provider files often carry DNS scripts (up/down): Shunt does
		// DNS itself, so they are commented out instead of refusing the file
		clean, removed := ovpnconf.Sanitize(req.Conf)
		if len(removed) > 0 {
			req.Conf = clean
			warn = append(warn, "not used from the OpenVPN file (Shunt does routing and DNS itself, no scripts): "+strings.Join(removed, ", "))
		}
		// separate certificate files can't be imported: dir ""
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
	d.mu.Lock()
	_, exists := d.cfg.Tunnels[req.Name]
	d.mu.Unlock()
	if exists {
		return nil, fmt.Errorf("a tunnel %q exists already", req.Name)
	}
	if err := os.MkdirAll(d.tunnelDir(), 0o700); err != nil {
		return nil, err
	}
	file := filepath.Join(d.tunnelDir(), req.Name+ext)
	auth := filepath.Join(d.tunnelDir(), req.Name+".auth")
	d.mu.Lock()
	used := map[string]bool{}
	for _, t := range d.cfg.Tunnels {
		used[d.absConf(t.Config)] = true
		if t.Auth != "" {
			used[d.absConf(t.Auth)] = true
		}
	}
	d.mu.Unlock()
	for _, f := range []string{file, auth, filepath.Join(d.tunnelDir(), req.Name+".conf"), filepath.Join(d.tunnelDir(), req.Name+".ovpn")} {
		if _, err := os.Stat(f); err != nil {
			continue
		}
		if used[f] {
			return nil, fmt.Errorf("%s belongs to another tunnel", f)
		}
		// left over from a tunnel removed by hand: replace it
		d.Log.Info("replacing orphaned tunnel file", "file", f)
		_ = os.Remove(f)
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
	cleanup := func() { os.Remove(file); os.Remove(auth) }
	raw, err := os.ReadFile(d.ConfigPath)
	if err != nil {
		cleanup()
		return nil, err
	}
	newRaw := strings.TrimRight(string(raw), "\n") + "\n" + block
	p, err := d.saveConfig([]byte(newRaw), "")
	if err != nil {
		cleanup()
		return nil, err
	}
	p.Warnings = append(p.Warnings, warn...)
	return p, nil
}

// deleteTunnel removes a tunnel that no rule uses anymore.
func (d *Daemon) deleteTunnel(name string) error {
	d.mu.Lock()
	cfg := *d.cfg
	t, ok := cfg.Tunnels[name]
	d.mu.Unlock()
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
	for n, tt := range cfg.Tunnels {
		if tt.Via == route {
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
	if _, err := d.saveConfig(raw, ""); err != nil {
		return err
	}
	for _, f := range []string{t.Config, t.Auth} {
		if p := d.absConf(f); f != "" && strings.HasPrefix(p, d.tunnelDir()+string(filepath.Separator)) {
			_ = os.Remove(p)
		}
	}
	return nil
}
