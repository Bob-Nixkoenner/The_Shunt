package winsplit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Quiet mode on Windows also switches off the sources of LLMNR, mDNS and
// NetBIOS over TCP/IP in the registry: Windows sends them ~1 s before the
// boot-time WFP filters take effect (lab D05). Earlier values are saved and
// put back when quiet mode ends; a value that already has the wanted content
// (policy, domain) is neither changed nor "restored".

const (
	dnsClientPolicyKey = `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`
	netbtIfacesKey     = `SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces`
)

// RegStore is the registry access (HKLM) the logic needs.
type RegStore interface {
	// GetDWORD returns the value and whether it exists.
	GetDWORD(key, name string) (uint32, bool, error)
	SetDWORD(key, name string, v uint32) error
	DeleteValue(key, name string) error
	SubKeys(key string) ([]string, error)
}

type regPrev struct {
	Key    string `json:"key"`
	Name   string `json:"name"`
	Want   uint32 `json:"want"`
	Exists bool   `json:"existed"`
	Value  uint32 `json:"value"`
}

type quietReg struct {
	mu    sync.Mutex
	store RegStore
	file  string
}

func newQuietReg(store RegStore, file string) *quietReg {
	return &quietReg{store: store, file: file}
}

func (q *quietReg) load() []regPrev {
	var l []regPrev
	if b, err := os.ReadFile(q.file); err == nil {
		_ = json.Unmarshal(b, &l)
	}
	return l
}

func (q *quietReg) save(l []regPrev) error {
	if err := os.MkdirAll(filepath.Dir(q.file), 0o755); err != nil {
		return err
	}
	b, _ := json.Marshal(l)
	tmp := q.file + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, q.file)
}

func (q *quietReg) targets() []regPrev {
	t := []regPrev{
		{Key: dnsClientPolicyKey, Name: "EnableMulticast", Want: 0},
		{Key: dnsClientPolicyKey, Name: "EnableMDNS", Want: 0},
	}
	subs, _ := q.store.SubKeys(netbtIfacesKey)
	for _, s := range subs {
		if strings.HasPrefix(s, "Tcpip_") {
			t = append(t, regPrev{Key: netbtIfacesKey + `\` + s, Name: "NetbiosOptions", Want: 2})
		}
	}
	return t
}

// apply sets the values (idempotent; also for adapters that appeared later).
func (q *quietReg) apply() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	saved := q.load()
	var firstErr error
	for _, t := range q.targets() {
		cur, ok, err := q.store.GetDWORD(t.Key, t.Name)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if ok && cur == t.Want {
			continue // already set by us (saved) or by the user/policy
		}
		t.Exists, t.Value = ok, cur
		saved = append(saved, t)
		if err := q.save(saved); err != nil { // save before changing
			return err
		}
		if err := q.store.SetDWORD(t.Key, t.Name, t.Want); err != nil {
			saved = saved[:len(saved)-1]
			_ = q.save(saved)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// restore puts the saved values back and removes the file.
func (q *quietReg) restore() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	var firstErr error
	var keep []regPrev
	for _, p := range q.load() {
		cur, ok, err := q.store.GetDWORD(p.Key, p.Name)
		if err == nil && (!ok || cur != p.Want) {
			continue // changed by someone else since: leave it
		}
		if p.Exists {
			err = q.store.SetDWORD(p.Key, p.Name, p.Value)
		} else {
			err = q.store.DeleteValue(p.Key, p.Name)
		}
		if err != nil {
			keep = append(keep, p)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	if len(keep) > 0 {
		_ = q.save(keep)
		return firstErr
	}
	_ = os.Remove(q.file)
	return firstErr
}
