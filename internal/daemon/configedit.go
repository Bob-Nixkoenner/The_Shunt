package daemon

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/Bob-Nixkoenner/the_shunt/internal/api"
	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
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
	v := api.ConfigView{Raw: string(raw), Config: d.cfg}
	for name, wc := range d.prep.Confs {
		ti := api.TunnelConfInfo{Name: name, DNS: wc.DNS}
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
	}
	d.mu.Unlock()
	if c.Daemon.Socket != cur.Socket || c.Daemon.SocketGroup != cur.SocketGroup || c.Daemon.CgroupRoot != cur.CgroupRoot || c.Daemon.APIAuth != cur.APIAuth {
		return nil, errors.New("the [daemon] socket/socket_group/cgroup_root/api_auth settings can only be changed in the file itself")
	}
	for name, t := range c.Tunnels {
		p := d.absConf(t.Config)
		if !oldPaths[p] && !strings.HasPrefix(p, d.tunnelDir()+string(filepath.Separator)) {
			return nil, fmt.Errorf("tunnel %q: config files must be in %s", name, d.tunnelDir())
		}
	}
	tmp := filepath.Join(filepath.Dir(d.ConfigPath), ".shunt.toml.candidate")
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return nil, err
	}
	defer os.Remove(tmp)
	return Prepare(tmp, root)
}

func (d *Daemon) absConf(p string) string {
	if !filepath.IsAbs(p) {
		p = filepath.Join(filepath.Dir(d.ConfigPath), p)
	}
	return filepath.Clean(p)
}

// saveConfig validates, writes and applies raw config text.
func (d *Daemon) saveConfig(raw []byte) (*Prepared, error) {
	d.saveMu.Lock()
	defer d.saveMu.Unlock()
	p, err := d.checkCandidate(raw)
	if err != nil {
		return nil, err
	}
	old, err := os.ReadFile(d.ConfigPath)
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

// importTunnel stores a wg-quick file and adds the tunnel to the config.
// The table is appended to the raw text, so comments in the file survive.
func (d *Daemon) importTunnel(req api.TunnelImport) (*Prepared, error) {
	if !tunnelNameRe.MatchString(req.Name) {
		return nil, errors.New("name: 1-10 characters a-z 0-9 -, starting with a letter or digit")
	}
	wc, err := wgconf.Parse(strings.NewReader(req.Conf))
	if err != nil {
		return nil, fmt.Errorf("WireGuard config: %w", err)
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
	file := filepath.Join(d.tunnelDir(), req.Name+".conf")
	if _, err := os.Stat(file); err == nil {
		return nil, fmt.Errorf("%s exists already", file)
	}
	if err := writeAtomic(file, []byte(req.Conf), 0o600); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(d.ConfigPath)
	if err != nil {
		os.Remove(file)
		return nil, err
	}
	block := fmt.Sprintf("\n[tunnel.%s]\nconfig = %q\n", req.Name, "tunnels/"+req.Name+".conf")
	if req.DNS != "" {
		block += fmt.Sprintf("dns = %q\n", req.DNS)
	}
	newRaw := strings.TrimRight(string(raw), "\n") + "\n" + block
	p, err := d.saveConfig([]byte(newRaw))
	if err != nil {
		os.Remove(file)
		return nil, err
	}
	if len(wc.Ignored) > 0 {
		p.Warnings = append(p.Warnings, "ignored in the WireGuard file: "+strings.Join(wc.Ignored, ", "))
	}
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
	if _, err := d.saveConfig(raw); err != nil {
		return err
	}
	if p := d.absConf(t.Config); strings.HasPrefix(p, d.tunnelDir()+string(filepath.Separator)) {
		_ = os.Remove(p)
	}
	return nil
}
