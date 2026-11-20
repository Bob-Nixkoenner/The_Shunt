package winsvc

// Mullvad module of the Windows service: the same as on Linux
// (internal/daemon/mullvad.go), with one difference. A change of the tunnel
// set restarts the service, so everything that makes or removes several
// tunnels (a chain, a logout) does it in ONE change to shunt.toml.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/api"
	"github.com/Bob-Nixkoenner/the_shunt/internal/mullvad"
	"github.com/Bob-Nixkoenner/the_shunt/internal/wgconf"
)

// mullvadAcct is one Mullvad login. The account number gives access to the
// whole Mullvad account, so it is never logged or sent to the UI.
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
}

const mullvadDefaultAccount = "main"

type mullvadState struct {
	mu     sync.Mutex // serializes login/connect/logout
	client mullvad.Client
	list   *mullvad.RelayList
	listAt time.Time
}

// the store lives in the tunnel folder: only SYSTEM and Administrators read it
func (m *Manager) mullvadPath() string { return filepath.Join(m.tunnelDir(), "mullvad-store.json") }

func (m *Manager) mullvadLoad() (*mullvadStore, error) {
	raw, err := os.ReadFile(m.mullvadPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s mullvadStore
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("mullvad-store.json: %w", err)
	}
	if len(s.Accounts) == 0 {
		return nil, nil
	}
	return &s, nil
}

func (m *Manager) mullvadSave(s *mullvadStore) error {
	if len(s.Accounts) == 0 {
		err := os.Remove(m.mullvadPath())
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if err := os.MkdirAll(m.tunnelDir(), 0o700); err != nil {
		return err
	}
	if m.Secure != nil {
		m.Secure(m.tunnelDir())
	}
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(m.mullvadPath(), raw, 0o600)
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
func (m *Manager) MullvadStatus() (api.MullvadStatus, error) {
	s, err := m.mullvadLoad()
	if err != nil || s == nil {
		return api.MullvadStatus{}, err
	}
	cfg := m.Current()
	st := api.MullvadStatus{LoggedIn: true}
	for name, a := range s.Accounts {
		st.Accounts = append(st.Accounts, api.MullvadAccount{Name: name, Account: maskAccount(a.Account), Device: a.DeviceName})
	}
	slices.SortFunc(st.Accounts, func(a, b api.MullvadAccount) int { return strings.Compare(a.Name, b.Name) })
	for name, e := range s.Exits {
		if cfg == nil {
			break
		}
		if _, ok := cfg.Tunnels[name]; ok { // tunnel removed by hand: forget it
			e.Tunnel = name
			st.Exits = append(st.Exits, e)
		}
	}
	slices.SortFunc(st.Exits, func(a, b api.MullvadExit) int { return strings.Compare(a.Tunnel, b.Tunnel) })
	return st, nil
}

// MullvadLogin registers a new WireGuard key of this computer as a device of
// the account. Several accounts can be logged in, each under its own name.
func (m *Manager) MullvadLogin(name, account string) error {
	m.mv.mu.Lock()
	defer m.mv.mu.Unlock()
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
	s, err := m.mullvadLoad()
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
	tok, err := m.mv.client.Token(ctx, account)
	if err != nil {
		return err
	}
	priv, pub, err := mullvad.NewKey()
	if err != nil {
		return err
	}
	dev, err := m.mv.client.AddDevice(ctx, tok, pub)
	if err != nil {
		return err
	}
	if s.Accounts == nil {
		s.Accounts = map[string]*mullvadAcct{}
	}
	s.Accounts[name] = &mullvadAcct{Account: account, DeviceID: dev.ID, DeviceName: dev.Name, PrivateKey: priv, IPv4: dev.IPv4, IPv6: dev.IPv6}
	if err := m.mullvadSave(s); err != nil {
		// do not leave an unusable device in the account
		_ = m.mv.client.DeleteDevice(ctx, tok, dev.ID)
		return err
	}
	log.Printf("mullvad: device registered (login %s, device %s)", name, dev.Name)
	return nil
}

// MullvadRelays returns countries and cities (list cached for 10 minutes).
func (m *Manager) MullvadRelays() ([]mullvad.Country, error) {
	l, err := m.mullvadList()
	if err != nil {
		return nil, err
	}
	return l.Countries(), nil
}

func (m *Manager) mullvadList() (*mullvad.RelayList, error) {
	m.mv.mu.Lock()
	cached, at := m.mv.list, m.mv.listAt
	m.mv.mu.Unlock()
	if cached != nil && time.Since(at) < 10*time.Minute {
		return cached, nil
	}
	ctx, cancel := mullvadCtx()
	defer cancel()
	l, err := m.mv.client.Relays(ctx)
	if err != nil {
		if cached != nil {
			return cached, nil
		}
		return nil, err
	}
	m.mv.mu.Lock()
	m.mv.list, m.mv.listAt = l, time.Now()
	m.mv.mu.Unlock()
	return l, nil
}

// hopDepth: how many tunnels the packets of a tunnel travel through before
// they leave (a via chain).
func (m *Manager) hopDepth(via string) int {
	cfg := m.Current()
	depth := 0
	for cfg != nil && via != "" && depth < 16 {
		name, ok := strings.CutPrefix(via, "tunnel:")
		if !ok {
			break
		}
		t, ok := cfg.Tunnels[name]
		if !ok {
			break
		}
		depth++
		via = t.Via
	}
	return depth
}

// pickAccount names the login a new tunnel uses.
func (s *mullvadStore) pickAccount(want string) (string, error) {
	if want != "" {
		if s.Accounts[want] == nil {
			return "", fmt.Errorf("no Mullvad account %q", want)
		}
		return want, nil
	}
	if len(s.Accounts) == 1 {
		for n := range s.Accounts {
			return n, nil
		}
	}
	if s.Accounts[mullvadDefaultAccount] != nil {
		return mullvadDefaultAccount, nil
	}
	return "", errors.New("several Mullvad accounts are logged in: say which one the tunnel uses")
}

// newHop is a tunnel to make: its WireGuard file and what it runs through.
type newHop struct {
	name, conf, via string
}

// addTunnels makes WireGuard tunnels in ONE change of shunt.toml (one restart).
// Nothing is left behind when it fails.
func (m *Manager) addTunnels(hops []newHop) error {
	m.mu.Lock()
	if m.cfg == nil {
		m.mu.Unlock()
		return errors.New("config not loaded")
	}
	for _, h := range hops {
		if !tunnelNameRe.MatchString(h.name) {
			m.mu.Unlock()
			return errors.New("name: 1-10 characters a-z 0-9 -, starting with a letter or digit")
		}
		if _, ok := m.cfg.Tunnels[h.name]; ok {
			m.mu.Unlock()
			return fmt.Errorf("a tunnel %q exists already", h.name)
		}
	}
	m.mu.Unlock()
	for _, h := range hops {
		if _, err := wgconf.Parse(strings.NewReader(h.conf)); err != nil {
			return fmt.Errorf("WireGuard config: %w", err)
		}
	}
	if err := os.MkdirAll(m.tunnelDir(), 0o700); err != nil {
		return err
	}
	if m.Secure != nil {
		m.Secure(m.tunnelDir())
	}
	var files []string
	undo := func() {
		for _, f := range files {
			_ = os.Remove(f)
		}
	}
	block := ""
	for _, h := range hops {
		file := filepath.Join(m.tunnelDir(), h.name+".conf")
		_ = os.Remove(file)
		_ = os.Remove(filepath.Join(m.tunnelDir(), h.name+".ovpn"))
		if err := writeAtomic(file, []byte(h.conf), 0o600); err != nil {
			undo()
			return err
		}
		files = append(files, file)
		block += fmt.Sprintf("\n[tunnel.%s]\nconfig = %q\n", h.name, "tunnels/"+h.name+".conf")
		if h.via != "" {
			block += fmt.Sprintf("via = %q\n", h.via)
		}
	}
	raw, err := os.ReadFile(m.path())
	if err != nil {
		undo()
		return err
	}
	if _, err := m.Save([]byte(strings.TrimRight(string(raw), "\n")+"\n"+block), ""); err != nil {
		undo()
		return err
	}
	return nil
}

// MullvadConnect creates the tunnel on a server, or moves an existing Mullvad
// tunnel to another one (the exit switch; its rules and routes stay).
func (m *Manager) MullvadConnect(req api.MullvadConnect) error {
	m.mv.mu.Lock()
	defer m.mv.mu.Unlock()
	return m.mullvadConnect(req)
}

func (m *Manager) mullvadConnect(req api.MullvadConnect) error {
	s, err := m.mullvadLoad()
	if err != nil {
		return err
	}
	if s == nil {
		return errors.New("log in to Mullvad first")
	}
	if req.Tunnel == "" {
		req.Tunnel = "mullvad"
	}
	l, err := m.mullvadListLocked()
	if err != nil {
		return err
	}
	cfg := m.Current()
	if cfg == nil {
		return errors.New("config not loaded")
	}
	cur, exists := cfg.Tunnels[req.Tunnel]
	prev, mine := s.Exits[req.Tunnel]
	mine = mine && exists
	acct := req.Account
	if acct == "" && mine {
		acct = prev.Account // switching the exit keeps the login
	}
	if acct, err = s.pickAccount(acct); err != nil {
		return err
	}
	a := s.Accounts[acct]
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
	conf, err := mullvad.Conf(a.PrivateKey, &mullvad.Device{IPv4: a.IPv4, IPv6: a.IPv6}, r, l.WireGuard.Gateway, mullvad.HopMTU(m.hopDepth(via)))
	if err != nil {
		return err
	}
	loc := l.Locations[r.Location]
	exit := api.MullvadExit{Tunnel: req.Tunnel, Account: acct, Hostname: r.Hostname, Country: loc.Country, City: loc.City, Provider: r.Provider}
	if mine {
		if err := m.mullvadMove(req.Tunnel, conf); err != nil {
			return err
		}
	} else if err := m.addTunnels([]newHop{{req.Tunnel, conf, req.Via}}); err != nil {
		return err
	}
	if s.Exits == nil {
		s.Exits = map[string]api.MullvadExit{}
	}
	s.Exits[req.Tunnel] = exit
	log.Printf("mullvad: tunnel %s on server %s (login %s)", req.Tunnel, r.Hostname, acct)
	return m.mullvadSave(s)
}

// mullvadListLocked is mullvadList for callers that hold m.mv.mu.
func (m *Manager) mullvadListLocked() (*mullvad.RelayList, error) {
	if m.mv.list != nil && time.Since(m.mv.listAt) < 10*time.Minute {
		return m.mv.list, nil
	}
	ctx, cancel := mullvadCtx()
	defer cancel()
	l, err := m.mv.client.Relays(ctx)
	if err != nil {
		if m.mv.list != nil {
			return m.mv.list, nil
		}
		return nil, err
	}
	m.mv.list, m.mv.listAt = l, time.Now()
	return l, nil
}

// mullvadMove swaps the WireGuard file of a tunnel and applies it (the
// service restarts); the old file comes back when the new setup does not check.
func (m *Manager) mullvadMove(name, conf string) error {
	cfg := m.Current()
	if cfg == nil {
		return errors.New("config not loaded")
	}
	t, ok := cfg.Tunnels[name]
	if !ok {
		return fmt.Errorf("no tunnel %q", name)
	}
	file := m.abs(t.Config)
	if filepath.Dir(file) != filepath.Clean(m.tunnelDir()) {
		return fmt.Errorf("tunnel %q: unexpected file location", name)
	}
	old, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	if err := writeAtomic(file, []byte(conf), 0o600); err != nil {
		return err
	}
	if err := m.Reload(); err != nil {
		_ = writeAtomic(file, old, 0o600)
		return fmt.Errorf("could not switch (previous server kept): %w", err)
	}
	return nil
}

// MullvadLogout removes one login: its Mullvad tunnels (that no rule uses)
// and its device at Mullvad. When a rule, a network or another tunnel still
// uses one of the tunnels, the login stays and the error says which.
func (m *Manager) MullvadLogout(name string) error {
	m.mv.mu.Lock()
	defer m.mv.mu.Unlock()
	if name == "" {
		name = mullvadDefaultAccount
	}
	s, err := m.mullvadLoad()
	if err != nil {
		return err
	}
	if s == nil || s.Accounts[name] == nil {
		return nil
	}
	a := s.Accounts[name]
	cfg := m.Current()
	var mine []string
	for tn, e := range s.Exits {
		if e.Account != name {
			continue
		}
		if cfg == nil || cfg.Tunnels[tn].Config == "" { // gone already
			delete(s.Exits, tn)
			continue
		}
		mine = append(mine, tn)
	}
	slices.Sort(mine)
	if len(mine) > 0 {
		if err := m.DeleteTunnels(mine...); err != nil {
			_ = m.mullvadSave(s)
			return fmt.Errorf("not logged out; these tunnels are still in use: %w", err)
		}
		for _, tn := range mine {
			delete(s.Exits, tn)
		}
	}
	// Deleting tunnels restarts the service, and that cuts this process's
	// connections for a few seconds (lab 20.11.: "connection closed by remote
	// host" on the token call, the device stayed at Mullvad while key and
	// number were gone here). So after a change of tunnels the call is tried
	// again a few times; without one it is tried once.
	tries := 1
	if len(mine) > 0 {
		tries = mullvadLogoutTries
	}
	var derr error
	for i := 0; i < tries; i++ {
		if i > 0 {
			time.Sleep(mullvadLogoutWait)
		}
		derr = m.mullvadRemoveDevice(a)
		if derr == nil {
			break
		}
	}
	if derr != nil {
		log.Printf("mullvad: device of login %s not removed at Mullvad (remove it on mullvad.net): %v", name, derr)
	}
	delete(s.Accounts, name)
	return m.mullvadSave(s)
}

// how often and how long apart the device removal is tried after tunnels were
// deleted (the restart of the service cuts connections for a few seconds)
var (
	mullvadLogoutTries = 5
	mullvadLogoutWait  = 5 * time.Second
)

// mullvadRemoveDevice logs in again with the account number and deletes the
// device of that login at Mullvad.
func (m *Manager) mullvadRemoveDevice(a *mullvadAcct) error {
	ctx, cancel := mullvadCtx()
	defer cancel()
	tok, err := m.mv.client.Token(ctx, a.Account)
	if err != nil {
		return fmt.Errorf("log in to remove the device: %w", err)
	}
	return m.mv.client.DeleteDevice(ctx, tok, a.DeviceID)
}

// MullvadChain builds a chain of Mullvad tunnels: hop i+1 runs through hop i.
// All hops are made in one change, or none.
func (m *Manager) MullvadChain(req api.MullvadChain) error {
	if !tunnelNameRe.MatchString(req.Name) || len(req.Name) > 8 {
		return errors.New("chain name: 1-8 characters a-z 0-9 -, starting with a letter or digit (the hops are named NAME1, NAME2, ...)")
	}
	m.mv.mu.Lock()
	defer m.mv.mu.Unlock()
	s, err := m.mullvadLoad()
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
	l, err := m.mullvadListLocked()
	if err != nil {
		return err
	}
	relays, err := l.PickChain(req.Hops, req.Entry, req.Exit)
	if err != nil {
		return err
	}
	cfg := m.Current()
	if cfg == nil {
		return errors.New("config not loaded")
	}
	for i := range relays {
		if _, ok := cfg.Tunnels[fmt.Sprintf("%s%d", req.Name, i+1)]; ok {
			return fmt.Errorf("a tunnel %s%d exists already: choose another chain name", req.Name, i+1)
		}
	}
	base := m.hopDepth(req.Via)
	via := req.Via
	var hops []newHop
	exits := map[string]api.MullvadExit{}
	for i, r := range relays {
		name := fmt.Sprintf("%s%d", req.Name, i+1)
		acct := accts[i%len(accts)]
		a := s.Accounts[acct]
		conf, err := mullvad.Conf(a.PrivateKey, &mullvad.Device{IPv4: a.IPv4, IPv6: a.IPv6}, r, l.WireGuard.Gateway, mullvad.HopMTU(base+i))
		if err != nil {
			return fmt.Errorf("hop %d (%s): %w", i+1, name, err)
		}
		hops = append(hops, newHop{name, conf, via})
		loc := l.Locations[r.Location]
		exits[name] = api.MullvadExit{Tunnel: name, Account: acct, Hostname: r.Hostname, Country: loc.Country, City: loc.City, Provider: r.Provider, Chain: req.Name}
		via = "tunnel:" + name
	}
	if err := m.addTunnels(hops); err != nil {
		return err
	}
	if s.Exits == nil {
		s.Exits = map[string]api.MullvadExit{}
	}
	for n, e := range exits {
		s.Exits[n] = e
	}
	log.Printf("mullvad: chain %s built, %d hops", req.Name, len(hops))
	return m.mullvadSave(s)
}

// MullvadChainDelete removes all hops of a chain in one change. A rule or
// network that uses one of them stops it.
func (m *Manager) MullvadChainDelete(name string) error {
	m.mv.mu.Lock()
	defer m.mv.mu.Unlock()
	s, err := m.mullvadLoad()
	if err != nil {
		return err
	}
	var hops []string
	if s != nil {
		cfg := m.Current()
		for tn, e := range s.Exits {
			if e.Chain != name {
				continue
			}
			if cfg == nil || cfg.Tunnels[tn].Config == "" { // gone already
				delete(s.Exits, tn)
				continue
			}
			hops = append(hops, tn)
		}
	}
	if len(hops) == 0 {
		if s != nil {
			_ = m.mullvadSave(s)
		}
		return fmt.Errorf("no chain %q", name)
	}
	slices.Sort(hops)
	if err := m.DeleteTunnels(hops...); err != nil {
		return fmt.Errorf("chain not removed: %w", err)
	}
	for _, tn := range hops {
		delete(s.Exits, tn)
	}
	return m.mullvadSave(s)
}

// mullvadRoutes are the /v1/mullvad routes (the same as shuntd's).
func (s *Server) mullvadRoutes(mux *http.ServeMux) {
	m := s.Cfg
	mux.HandleFunc("GET /v1/mullvad", func(w http.ResponseWriter, r *http.Request) {
		st, err := m.MullvadStatus()
		if err != nil {
			fail(w, http.StatusInternalServerError, err)
			return
		}
		ok(w, st)
	})
	mux.HandleFunc("GET /v1/mullvad/relays", func(w http.ResponseWriter, r *http.Request) {
		cs, err := m.MullvadRelays()
		if err != nil {
			fail(w, http.StatusBadGateway, err)
			return
		}
		ok(w, cs)
	})
	post := func(path, what string, do func(r *http.Request, w http.ResponseWriter) (bool, error)) {
		mux.HandleFunc("POST /v1/mullvad/"+path, func(w http.ResponseWriter, r *http.Request) {
			if !s.may(w, r, what) {
				return
			}
			done, err := do(r, w)
			switch {
			case !done: // the body did not decode: answered already
			case err != nil:
				fail(w, http.StatusUnprocessableEntity, err)
			default:
				w.WriteHeader(http.StatusNoContent)
			}
		})
	}
	body := func(w http.ResponseWriter, r *http.Request, v any) bool {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(v); err != nil {
			fail(w, http.StatusBadRequest, err)
			return false
		}
		return true
	}
	post("login", "logging in to Mullvad", func(r *http.Request, w http.ResponseWriter) (bool, error) {
		var req api.MullvadLogin
		if !body(w, r, &req) {
			return false, nil
		}
		return true, m.MullvadLogin(req.Name, req.Account)
	})
	post("connect", "changing a Mullvad exit", func(r *http.Request, w http.ResponseWriter) (bool, error) {
		var req api.MullvadConnect
		if !body(w, r, &req) {
			return false, nil
		}
		return true, m.MullvadConnect(req)
	})
	post("chain", "building a Mullvad chain", func(r *http.Request, w http.ResponseWriter) (bool, error) {
		var req api.MullvadChain
		if !body(w, r, &req) {
			return false, nil
		}
		return true, m.MullvadChain(req)
	})
	post("chain/delete", "deleting a Mullvad chain", func(r *http.Request, w http.ResponseWriter) (bool, error) {
		var req api.MullvadChainDelete
		if !body(w, r, &req) {
			return false, nil
		}
		return true, m.MullvadChainDelete(req.Name)
	})
	post("logout", "logging out of Mullvad", func(r *http.Request, w http.ResponseWriter) (bool, error) {
		var req api.MullvadLogout
		if r.ContentLength != 0 && !body(w, r, &req) {
			return false, nil
		}
		return true, m.MullvadLogout(req.Name)
	})
}
