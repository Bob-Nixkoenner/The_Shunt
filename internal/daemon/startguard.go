package daemon

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/check"
)

// The start guard: a config the service accepted can still keep shuntd from
// coming up (a crash at start, 2026-11-12: Max Security killed it at every
// start). Without the socket neither the window nor the CLI can change the
// setting back. So every start is counted until it has run for a while; after
// startGuardTries starts in a row with the same config that never got there,
// shuntd puts back the previous config (shunt.toml.bak, written by every
// save through the API), keeps the failed one as shunt.toml.failed and says
// so in the status.
const (
	startGuardTries  = 3
	startGuardSettle = 30 * time.Second
)

type startGuardState struct {
	Config  string `json:"config"`  // sha256 of the config these starts used
	Pending int    `json:"pending"` // starts with it that did not settle
}

// startGuardPath: systemd's StateDirectory, else next to the config.
func (d *Daemon) startGuardPath() string {
	if dir, _, _ := strings.Cut(os.Getenv("STATE_DIRECTORY"), ":"); dir != "" {
		return filepath.Join(dir, "start-guard.json")
	}
	return filepath.Join(filepath.Dir(d.ConfigPath), "start-guard.json")
}

func cfgHash(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// startGuardBegin runs before the config is read. It counts this start and,
// when the config has failed often enough, puts the previous one back.
func (d *Daemon) startGuardBegin() {
	cur, err := os.ReadFile(d.ConfigPath)
	if err != nil {
		return
	}
	var st startGuardState
	if b, err := os.ReadFile(d.startGuardPath()); err == nil {
		_ = json.Unmarshal(b, &st)
	}
	if h := cfgHash(cur); st.Config != h {
		st = startGuardState{Config: h}
	}
	if st.Pending >= startGuardTries {
		// only a different previous config helps; after a restore .bak and
		// the config are the same, so a failing old config never ping-pongs
		bak, err := os.ReadFile(d.ConfigPath + ".bak")
		if err == nil && cfgHash(bak) != st.Config {
			if err := writeAtomic(d.ConfigPath+".failed", cur, 0o600); err == nil {
				if err := writeAtomic(d.ConfigPath, bak, 0o644); err == nil {
					d.Log.Error("shuntd did not get through its start with the last saved config, the previous one is back",
						"starts", st.Pending, "failed_config", d.ConfigPath+".failed")
					d.mu.Lock()
					d.startRestored = st.Pending
					d.mu.Unlock()
					st = startGuardState{Config: cfgHash(bak)}
				}
			}
		}
	}
	st.Pending++
	d.startGuardWrite(st)
}

// startGuardDone: this start got through (it ran startGuardSettle, or it
// ended in an orderly way before).
func (d *Daemon) startGuardDone() {
	var st startGuardState
	if b, err := os.ReadFile(d.startGuardPath()); err == nil {
		_ = json.Unmarshal(b, &st)
	}
	if st.Pending == 0 {
		return
	}
	st.Pending = 0
	d.startGuardWrite(st)
}

func (d *Daemon) startGuardWrite(st startGuardState) {
	b, _ := json.Marshal(st)
	if err := writeAtomic(d.startGuardPath(), b, 0o600); err != nil {
		d.Log.Debug("start guard: cannot write its state", "err", err)
	}
}

// startGuardNote is the status notice after a restore.
func (d *Daemon) startGuardNote() []check.Finding {
	if d.startRestored == 0 {
		return nil
	}
	return []check.Finding{check.Note("config.restored",
		"shuntd did not get through its start {n} times in a row with the last saved settings, so it went back to the previous ones. The failed settings are kept in {file}.",
		"n", strconv.Itoa(d.startRestored), "file", d.ConfigPath+".failed")}
}
