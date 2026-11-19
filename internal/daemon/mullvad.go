package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/api"
	"github.com/Bob-Nixkoenner/the_shunt/internal/mullvad"
)

// mullvadStore is what Shunt keeps about the Mullvad login: root-only file
// next to the config. The account number is the secret that gives access to
// the whole Mullvad account, so it is never logged or sent to the UI.
type mullvadStore struct {
	Account    string                     `json:"account"`
	DeviceID   string                     `json:"device_id"`
	DeviceName string                     `json:"device_name"`
	PrivateKey string                     `json:"private_key"`
	IPv4       string                     `json:"ipv4"`
	IPv6       string                     `json:"ipv6"`
	Exits      map[string]api.MullvadExit `json:"exits,omitempty"` // tunnel -> server
}

type mullvadState struct {
	mu     sync.Mutex // serializes login/connect/logout
	client mullvad.Client
	list   *mullvad.RelayList
	listAt time.Time
}

func (d *Daemon) mullvadPath() string {
	return filepath.Join(filepath.Dir(d.ConfigPath), "mullvad.json")
}

func (d *Daemon) mullvadLoad() (*mullvadStore, error) {
	raw, err := os.ReadFile(d.mullvadPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s mullvadStore
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("mullvad.json: %w", err)
	}
	return &s, nil
}

func (d *Daemon) mullvadSave(s *mullvadStore) error {
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(d.mullvadPath(), raw, 0o600)
}

func mullvadCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 30*time.Second)
}

// MullvadStatus reports the login and the servers of the Mullvad tunnels.
func (d *Daemon) MullvadStatus() (api.MullvadStatus, error) {
	s, err := d.mullvadLoad()
	if err != nil || s == nil {
		return api.MullvadStatus{}, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	st := api.MullvadStatus{LoggedIn: true, Device: s.DeviceName}
	if n := len(s.Account); n >= 4 {
		st.Account = "••••" + s.Account[n-4:]
	}
	for name, e := range s.Exits {
		if _, ok := d.cfg.Tunnels[name]; ok { // tunnel removed by hand: forget it
			e.Tunnel = name
			st.Exits = append(st.Exits, e)
		}
	}
	slices.SortFunc(st.Exits, func(a, b api.MullvadExit) int { return strings.Compare(a.Tunnel, b.Tunnel) })
	return st, nil
}

// MullvadLogin registers a new WireGuard key of this computer as a device.
func (d *Daemon) MullvadLogin(account string) error {
	d.mv.mu.Lock()
	defer d.mv.mu.Unlock()
	account, err := mullvad.NormalizeAccount(account)
	if err != nil {
		return err
	}
	if s, err := d.mullvadLoad(); err != nil {
		return err
	} else if s != nil {
		return errors.New("already logged in to Mullvad; log out first")
	}
	ctx, cancel := mullvadCtx()
	defer cancel()
	tok, err := d.mv.client.Token(ctx, account)
	if err != nil {
		return err
	}
	priv, pub, err := mullvad.NewKey()
	if err != nil {
		return err
	}
	dev, err := d.mv.client.AddDevice(ctx, tok, pub)
	if err != nil {
		return err
	}
	s := &mullvadStore{Account: account, DeviceID: dev.ID, DeviceName: dev.Name, PrivateKey: priv, IPv4: dev.IPv4, IPv6: dev.IPv6}
	if err := d.mullvadSave(s); err != nil {
		// do not leave an unusable device in the account
		_ = d.mv.client.DeleteDevice(ctx, tok, dev.ID)
		return err
	}
	d.Log.Info("mullvad: device registered", "device", dev.Name)
	return nil
}

// MullvadRelays returns countries and cities (list cached for 10 minutes).
func (d *Daemon) MullvadRelays() ([]mullvad.Country, error) {
	l, err := d.mullvadList()
	if err != nil {
		return nil, err
	}
	return l.Countries(), nil
}

func (d *Daemon) mullvadList() (*mullvad.RelayList, error) {
	d.mv.mu.Lock()
	cached, at := d.mv.list, d.mv.listAt
	d.mv.mu.Unlock()
	if cached != nil && time.Since(at) < 10*time.Minute {
		return cached, nil
	}
	ctx, cancel := mullvadCtx()
	defer cancel()
	l, err := d.mv.client.Relays(ctx)
	if err != nil {
		if cached != nil {
			return cached, nil
		}
		return nil, err
	}
	d.mv.mu.Lock()
	d.mv.list, d.mv.listAt = l, time.Now()
	d.mv.mu.Unlock()
	return l, nil
}

// MullvadConnect creates the tunnel on a server, or moves an existing Mullvad
// tunnel to another one (the exit switch; its rules and routes stay).
func (d *Daemon) MullvadConnect(req api.MullvadConnect) error {
	s, err := d.mullvadLoad()
	if err != nil {
		return err
	}
	if s == nil {
		return errors.New("log in to Mullvad first")
	}
	if req.Tunnel == "" {
		req.Tunnel = "mullvad"
	}
	l, err := d.mullvadList()
	if err != nil {
		return err
	}
	d.mv.mu.Lock()
	defer d.mv.mu.Unlock()
	r, err := l.Pick(mullvad.Choice{Country: req.Country, City: req.City, Hostname: req.Hostname})
	if err != nil {
		return err
	}
	conf, err := mullvad.Conf(s.PrivateKey, &mullvad.Device{IPv4: s.IPv4, IPv6: s.IPv6}, r, l.WireGuard.Gateway)
	if err != nil {
		return err
	}
	loc := l.Locations[r.Location]
	exit := api.MullvadExit{Tunnel: req.Tunnel, Hostname: r.Hostname, Country: loc.Country, City: loc.City}

	d.mu.Lock()
	_, exists := d.cfg.Tunnels[req.Tunnel]
	d.mu.Unlock()
	if _, mine := s.Exits[req.Tunnel]; mine && exists {
		if err := d.mullvadMove(req.Tunnel, conf); err != nil {
			return err
		}
	} else {
		if _, err := d.importTunnel(api.TunnelImport{Name: req.Tunnel, Conf: conf, Via: req.Via}); err != nil {
			return err
		}
	}
	if s.Exits == nil {
		s.Exits = map[string]api.MullvadExit{}
	}
	s.Exits[req.Tunnel] = exit
	d.Log.Info("mullvad: tunnel on server", "tunnel", req.Tunnel, "server", r.Hostname)
	return d.mullvadSave(s)
}

// mullvadMove swaps the WireGuard file of a tunnel and applies it; the old
// file comes back when the new setup does not apply.
func (d *Daemon) mullvadMove(name, conf string) error {
	d.mu.Lock()
	t, ok := d.cfg.Tunnels[name]
	root := ""
	if d.plan != nil {
		root = d.plan.CgroupRoot
	}
	d.mu.Unlock()
	if !ok {
		return fmt.Errorf("no tunnel %q", name)
	}
	file := d.absConf(t.Config)
	if filepath.Dir(file) != d.tunnelDir() {
		return fmt.Errorf("tunnel %q: unexpected file location", name)
	}
	d.saveMu.Lock()
	defer d.saveMu.Unlock()
	old, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	if err := writeAtomic(file, []byte(conf), 0o600); err != nil {
		return err
	}
	if err := d.reload(root); err != nil {
		_ = writeAtomic(file, old, 0o600)
		if err2 := d.reload(root); err2 != nil {
			d.Log.Error("restoring the previous Mullvad server failed", "err", err2)
		}
		return fmt.Errorf("could not switch (previous server restored): %w", err)
	}
	return nil
}

// MullvadLogout removes the device at Mullvad, the Mullvad tunnels that no
// rule uses and the stored key. Tunnels that rules still use stay (dead,
// their key is revoked) and are named in the error.
func (d *Daemon) MullvadLogout() error {
	d.mv.mu.Lock()
	defer d.mv.mu.Unlock()
	s, err := d.mullvadLoad()
	if err != nil {
		return err
	}
	if s == nil {
		return nil
	}
	var stuck []string
	for name := range s.Exits {
		err := d.deleteTunnel(name)
		if err != nil && !strings.Contains(err.Error(), "no tunnel") {
			stuck = append(stuck, fmt.Sprintf("%s (%v)", name, err))
		}
	}
	if len(stuck) > 0 {
		return errors.New("not logged out; these tunnels are still in use: " + strings.Join(stuck, "; "))
	}
	ctx, cancel := mullvadCtx()
	defer cancel()
	if tok, err := d.mv.client.Token(ctx, s.Account); err == nil {
		if err := d.mv.client.DeleteDevice(ctx, tok, s.DeviceID); err != nil {
			d.Log.Warn("mullvad: device not removed at Mullvad", "err", err)
		}
	} else {
		d.Log.Warn("mullvad: could not log in to remove the device", "err", err)
	}
	return os.Remove(d.mullvadPath())
}
