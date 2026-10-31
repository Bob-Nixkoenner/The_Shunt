package ui

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// UI preferences (folded sections, theme, graph range ...) are kept in the
// user's config folder, not only in the page's localStorage: that is bound to
// the address of the page, which changes with every `shunt ui` start.
// Only keys with the prefix "shunt-" are stored.

var uiStateMu sync.Mutex

const (
	uiStatePrefix  = "shunt-"
	uiStateMaxKeys = 300
	uiStateMaxSize = 128 << 10
)

func uiStatePath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "shunt", "ui-state.json")
}

func loadUIState() map[string]string {
	out := map[string]string{}
	p := uiStatePath()
	if p == "" {
		return out
	}
	if b, err := os.ReadFile(p); err == nil {
		_ = json.Unmarshal(b, &out)
	}
	return out
}

// mergeUIState applies changes (a null value removes a key) and saves.
func mergeUIState(changes map[string]*string) (map[string]string, error) {
	uiStateMu.Lock()
	defer uiStateMu.Unlock()
	st := loadUIState()
	for k, v := range changes {
		if !strings.HasPrefix(k, uiStatePrefix) || len(k) > 200 {
			continue
		}
		if v == nil {
			delete(st, k)
		} else if len(*v) <= 2000 {
			st[k] = *v
		}
	}
	if len(st) > uiStateMaxKeys {
		return st, nil // runaway page: keep what is there
	}
	b, err := json.Marshal(st)
	if err != nil || len(b) > uiStateMaxSize {
		return st, err
	}
	p := uiStatePath()
	if p == "" {
		return st, nil
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return st, err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return st, err
	}
	return st, os.Rename(tmp, p)
}

// levelOf maps the old Normal/Expert view mode to the level that replaced
// it (Simple/Pro/Opsec); "" = not decided yet.
func levelOf(viewMode string) string {
	switch viewMode {
	case "normal":
		return "simple"
	case "expert":
		return "pro"
	}
	return ""
}

// migrateUIState loads the ui-state and stores the level under its new key
// "shunt-level" when only the old "shunt-view-mode" is there. The old key
// stays, for an older version of the page.
func migrateUIState() map[string]string {
	uiStateMu.Lock()
	st := loadUIState()
	uiStateMu.Unlock()
	if st["shunt-level"] != "" {
		return st
	}
	l := levelOf(st["shunt-view-mode"])
	if l == "" {
		return st
	}
	if saved, err := mergeUIState(map[string]*string{"shunt-level": &l}); err == nil {
		return saved
	}
	st["shunt-level"] = l
	return st
}
