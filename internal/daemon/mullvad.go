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

// mullvadAcct is one Mullvad login: root-only file next to the config. The
// account number gives access to the whole Mullvad account, so it is never
// logged or sent to the UI.
type mullvadAcct struct {
	Account    string `json:"account"`
	DeviceID   string `json:"device_id"`
	DeviceName string `json:"device_name"`
	PrivateKey string `json:"private_key"`
	IPv4       string `json:"ipv4"`
	IPv6       string `json:"ipv6"`
}

// mullvadStore: the logins by name and the server of each Mullvad tunnel.
type mullvadStore struct {
	Accounts map[string]*mullvadAcct    `json:"accounts,omitempty"`
	Exits    map[string]api.MullvadExit `json:"exits,omitempty"` // tunnel -> server

	// the first version kept one login at the top level: read, then saved
	// in the new form
	Account    string `json:"account,omitempty"`
	DeviceID   string `json:"device_id,omitempty"`
	DeviceName string `json:"device_name,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`
	IPv4       string `json:"ipv4,omitempty"`
	IPv6       string `json:"ipv6,omitempty"`
}

const mullvadDefaultAccount = "main"

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
	if s.Account != "" && s.Accounts == nil {
		s.Accounts = map[string]*mullvadAcct{mullvadDefaultAccount: {Account: s.Account, DeviceID: s.DeviceID,
			DeviceName: s.DeviceName, PrivateKey: s.PrivateKey, IPv4: s.IPv4, IPv6: s.IPv6}}
		for n, e := range s.Exits {
			e.Account = mullvadDefaultAccount
			s.Exits[n] = e
		}
	}
	s.Account, s.DeviceID, s.DeviceName, s.PrivateKey, s.IPv4, s.IPv6 = "", "", "", "", "", ""
	if len(s.Accounts) == 0 {
		return nil, nil
	}
	return &s, nil
}

func (d *Daemon) mullvadSave(s *mullvadStore) error {
	if len(s.Accounts) == 0 {
		err := os.Remove(d.mullvadPath())
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(d.mullvadPath(), raw, 0o600)
}

func mullvadCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 30*time.Second)
}

func maskAccount(a string) string {
	if n := len(a); n >= 4 {
		return "••••" + a[n-4:]
	}
	return ""
}

// MullvadStatus reports the logins and the servers of the Mullvad tunnels.
func (d *Daemon) MullvadStatus() (api.MullvadStatus, error) {
	s, err := d.mullvadLoad()
	if err != nil || s == nil {
		return api.MullvadStatus{}, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	st := api.MullvadStatus{LoggedIn: true}
	for name, a := range s.Accounts {
		st.Accounts = append(st.Accounts, api.MullvadAccount{Name: name, Account: maskAccount(a.Account), Device: a.DeviceName})
	}
	slices.SortFunc(st.Accounts, func(a, b api.MullvadAccount) int { return strings.Compare(a.Name, b.Name) })
	for name, e := range s.Exits {
		if _, ok := d.cfg.Tunnels[name]; ok { // tunnel removed by hand: forget it
			e.Tunnel = name
			st.Exits = append(st.Exits, e)
		}
	}
	slices.SortFunc(st.Exits, func(a, b api.MullvadExit) int { return strings.Compare(a.Tunnel, b.Tunnel) })
	return st, nil
}

// MullvadLogin registers a new WireGuard key of this computer as a device of
// the account. Several accounts can be logged in, each under its own name.
func (d *Daemon) MullvadLogin(name, account string) error {
	d.mv.mu.Lock()
	defer d.mv.mu.Unlock()
	if name == "" {
		name = mullvadDefaultAccount
	}
	if !tunnelNameRe.MatchString(name) {
		return errors.New("account name: 1-10 characters a-z 0-9 -, starting with a letter or digit")
	}
	account, err := mullvad.NormalizeAccount(account)
	if err != nil {
		return err
	}
	s, err := d.mullvadLoad()
	if err != nil {
		return err
	}
	if s == nil {
		s = &mullvadStore{}
	}
	if s.Accounts[name] != nil {
		return fmt.Errorf("an account %q is logged in already; log it out first or choose another name", name)
	}
	for n, a := range s.Accounts {
		if a.Account == account {
			return fmt.Errorf("this account is logged in already (as %q)", n)
		}
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
	if s.Accounts == nil {
		s.Accounts = map[string]*mullvadAcct{}
	}
	s.Accounts[name] = &mullvadAcct{Account: account, DeviceID: dev.ID, DeviceName: dev.Name, PrivateKey: priv, IPv4: dev.IPv4, IPv6: dev.IPv6}
	if err := d.mullvadSave(s); err != nil {
		// do not leave an unusable device in the account
		_ = d.mv.client.DeleteDevice(ctx, tok, dev.ID)
		return err
	}
	d.Log.Info("mullvad: device registered", "login", name, "device", dev.Name)
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

// hopDepth: how many tunnels the packets of a tunnel travel through before
// they leave (a via chain).
func (d *Daemon) hopDepth(via string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	depth := 0
	for via != "" && depth < 16 {
		name, ok := strings.CutPrefix(via, "tunnel:")
		if !ok {
			break
		}
		t, ok := d.cfg.Tunnels[name]
		if !ok {
			break
		}
		depth++
		via = t.Via
	}
	return depth
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
	d.mu.Lock()
	cur, exists := d.cfg.Tunnels[req.Tunnel]
	d.mu.Unlock()
	prev, mine := s.Exits[req.Tunnel]
	mine = mine && exists
	acct := req.Account
	if acct == "" && mine {
		acct = prev.Account // switching the exit keeps the login
	}
	if acct == "" {
		if len(s.Accounts) == 1 {
			for n := range s.Accounts {
				acct = n
			}
		} else if s.Accounts[mullvadDefaultAccount] != nil {
			acct = mullvadDefaultAccount
		} else {
			return errors.New("several Mullvad accounts are logged in: say which one the tunnel uses")
		}
	}
	a := s.Accounts[acct]
	if a == nil {
		return fmt.Errorf("no Mullvad account %q", acct)
	}
	if mine && req.Account != "" && req.Account != prev.Account {
		return fmt.Errorf("tunnel %q uses account %q; to change that, remove the tunnel and add it again", req.Tunnel, prev.Account)
	}
	r, err := l.Pick(mullvad.Choice{Country: req.Country, City: req.City, Hostname: req.Hostname})
	if err != nil {
		return err
	}
	via := req.Via
	if mine {
		via = cur.Via
	}
	conf, err := mullvad.Conf(a.PrivateKey, &mullvad.Device{IPv4: a.IPv4, IPv6: a.IPv6}, r, l.WireGuard.Gateway, mullvad.HopMTU(d.hopDepth(via)))
	if err != nil {
		return err
	}
	loc := l.Locations[r.Location]
	exit := api.MullvadExit{Tunnel: req.Tunnel, Account: acct, Hostname: r.Hostname, Country: loc.Country, City: loc.City, Provider: r.Provider}

	if mine {
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
	d.Log.Info("mullvad: tunnel on server", "tunnel", req.Tunnel, "login", acct, "server", r.Hostname)
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

// MullvadLogout removes one login: its Mullvad tunnels (that no rule uses)
// and its device at Mullvad. Tunnels that rules or other tunnels still use
// keep the login in place; they are named in the error.
func (d *Daemon) MullvadLogout(name string) error {
	d.mv.mu.Lock()
	defer d.mv.mu.Unlock()
	if name == "" {
		name = mullvadDefaultAccount
	}
	s, err := d.mullvadLoad()
	if err != nil {
		return err
	}
	if s == nil || s.Accounts[name] == nil {
		return nil
	}
	a := s.Accounts[name]
	// the tunnels of this login: a chain has to come down from the outside in
	var mine []string
	for tn, e := range s.Exits {
		if e.Account == name {
			mine = append(mine, tn)
		}
	}
	var stuck []string
	for range mine { // a few passes: deleting one frees the one it runs through
		stuck = stuck[:0]
		var left []string
		for _, tn := range mine {
			if err := d.deleteTunnel(tn); err != nil {
				if strings.Contains(err.Error(), "no tunnel") {
					delete(s.Exits, tn)
					continue
				}
				left = append(left, tn)
				stuck = append(stuck, fmt.Sprintf("%s (%v)", tn, err))
				continue
			}
			delete(s.Exits, tn)
		}
		mine = left
		if len(mine) == 0 {
			break
		}
	}
	if len(mine) > 0 {
		_ = d.mullvadSave(s)
		return errors.New("not logged out; these tunnels are still in use: " + strings.Join(stuck, "; "))
	}
	ctx, cancel := mullvadCtx()
	defer cancel()
	if tok, err := d.mv.client.Token(ctx, a.Account); err == nil {
		if err := d.mv.client.DeleteDevice(ctx, tok, a.DeviceID); err != nil {
			d.Log.Warn("mullvad: device not removed at Mullvad", "login", name, "err", err)
		}
	} else {
		d.Log.Warn("mullvad: could not log in to remove the device", "login", name, "err", err)
	}
	delete(s.Accounts, name)
	return d.mullvadSave(s)
}

// MullvadChain builds a chain of Mullvad tunnels: hop i+1 runs through hop i.
// When a hop cannot be made, the ones made so far are removed again.
func (d *Daemon) MullvadChain(req api.MullvadChain) error {
	if !tunnelNameRe.MatchString(req.Name) || len(req.Name) > 8 {
		return errors.New("chain name: 1-8 characters a-z 0-9 -, starting with a letter or digit (the hops are named NAME1, NAME2, ...)")
	}
	s, err := d.mullvadLoad()
	if err != nil {
		return err
	}
	if s == nil {
		return errors.New("log in to Mullvad first")
	}
	accts := req.Accounts
	if len(accts) == 0 {
		for n := range s.Accounts {
			accts = append(accts, n)
		}
		slices.Sort(accts)
	}
	for _, a := range accts {
		if s.Accounts[a] == nil {
			return fmt.Errorf("no Mullvad account %q", a)
		}
	}
	l, err := d.mullvadList()
	if err != nil {
		return err
	}
	relays, err := l.PickChain(req.Hops, req.Entry, req.Exit)
	if err != nil {
		return err
	}
	d.mu.Lock()
	for i := range relays {
		if _, ok := d.cfg.Tunnels[fmt.Sprintf("%s%d", req.Name, i+1)]; ok {
			d.mu.Unlock()
			return fmt.Errorf("a tunnel %s%d exists already: choose another chain name", req.Name, i+1)
		}
	}
	d.mu.Unlock()
	var made []string
	via := req.Via
	for i, r := range relays {
		name := fmt.Sprintf("%s%d", req.Name, i+1)
		err := d.MullvadConnect(api.MullvadConnect{Tunnel: name, Account: accts[i%len(accts)], Hostname: r.Hostname, Via: via})
		if err != nil {
			d.Log.Warn("mullvad: chain failed, removing the hops made", "hop", name, "err", err)
			d.mullvadUndo(made)
			return fmt.Errorf("hop %d (%s): %w", i+1, name, err)
		}
		made = append(made, name)
		via = "tunnel:" + name
	}
	d.mv.mu.Lock()
	if s2, err := d.mullvadLoad(); err == nil && s2 != nil {
		for _, n := range made {
			e := s2.Exits[n]
			e.Chain = req.Name
			s2.Exits[n] = e
		}
		_ = d.mullvadSave(s2)
	}
	d.mv.mu.Unlock()
	d.Log.Info("mullvad: chain built", "name", req.Name, "hops", len(made))
	return nil
}

// MullvadChainDelete removes all hops of a chain, last hop first. A hop that
// a rule or another tunnel still uses stops it (the hops after it are
// already gone then); the error names it.
func (d *Daemon) MullvadChainDelete(name string) error {
	d.mv.mu.Lock()
	defer d.mv.mu.Unlock()
	s, err := d.mullvadLoad()
	if err != nil {
		return err
	}
	var hops []string
	if s != nil {
		for tn, e := range s.Exits {
			if e.Chain == name {
				hops = append(hops, tn)
			}
		}
	}
	if len(hops) == 0 {
		return fmt.Errorf("no chain %q", name)
	}
	slices.SortFunc(hops, func(a, b string) int { return strings.Compare(b, a) }) // NAME3, NAME2, NAME1
	for _, tn := range hops {
		if err := d.deleteTunnel(tn); err != nil && !strings.Contains(err.Error(), "no tunnel") {
			_ = d.mullvadSave(s)
			return fmt.Errorf("chain not fully removed: %w", err)
		}
		delete(s.Exits, tn)
	}
	return d.mullvadSave(s)
}

// mullvadUndo removes tunnels made a moment ago, last hop first.
func (d *Daemon) mullvadUndo(names []string) {
	d.mv.mu.Lock()
	defer d.mv.mu.Unlock()
	s, _ := d.mullvadLoad()
	for i := len(names) - 1; i >= 0; i-- {
		if err := d.deleteTunnel(names[i]); err != nil {
			d.Log.Error("mullvad: could not remove a hop", "tunnel", names[i], "err", err)
		}
		if s != nil {
			delete(s.Exits, names[i])
		}
	}
	if s != nil {
		_ = d.mullvadSave(s)
	}
}
