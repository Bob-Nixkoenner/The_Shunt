package daemon

import (
	"fmt"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
)

// sleeper is a tunnel that is switched off for a while.
type sleeper struct {
	until time.Time
	timer *time.Timer
}

const (
	minSleep = time.Minute
	maxSleep = 24 * time.Hour
)

// sleepSet lists the sleeping tunnels (for Env.Sleep).
func (d *Daemon) sleepSet() map[string]bool {
	d.sleepMu.Lock()
	defer d.sleepMu.Unlock()
	m := map[string]bool{}
	for n := range d.sleepers {
		m[n] = true
	}
	return m
}

// sleepLeft: seconds until tunnel n wakes up (0: not asleep).
func (d *Daemon) sleepLeft(n string) int {
	d.sleepMu.Lock()
	defer d.sleepMu.Unlock()
	if s, ok := d.sleepers[n]; ok {
		if l := time.Until(s.until); l > 0 {
			return int(l.Seconds()) + 1
		}
	}
	return 0
}

// lockedFileCfg is fileCfg for callers that hold d.mu.
func (d *Daemon) lockedFileCfg() config.Config { return d.fileCfgOf(*d.cfg) }

// fileCfg is the running config as the file has it: sleeping is not part of
// the file, so a tunnel that only sleeps is never written as disabled.
func (d *Daemon) fileCfg() config.Config {
	d.mu.Lock()
	cfg := *d.cfg
	d.mu.Unlock()
	return d.fileCfgOf(cfg)
}

func (d *Daemon) fileCfgOf(cfg config.Config) config.Config {
	sl := d.sleepSet()
	if len(sl) == 0 {
		return cfg
	}
	file, err := config.Load(d.ConfigPath)
	if err != nil {
		return cfg
	}
	ts := make(map[string]config.Tunnel, len(cfg.Tunnels))
	for n, t := range cfg.Tunnels {
		if sl[n] {
			t.Disabled = file.Tunnels[n].Disabled
		}
		ts[n] = t
	}
	cfg.Tunnels = ts
	return cfg
}

func (d *Daemon) stopSleep(name string) bool {
	d.sleepMu.Lock()
	defer d.sleepMu.Unlock()
	s, ok := d.sleepers[name]
	if ok {
		s.timer.Stop()
		delete(d.sleepers, name)
	}
	return ok
}

func (d *Daemon) reloadNow() error {
	d.mu.Lock()
	root := d.plan.CgroupRoot
	d.mu.Unlock()
	return d.reload(root)
}

// setTunnelState switches a tunnel "on" or "off" (config file, lasting) or
// lets it "sleep" for dur (memory only). An off or sleeping tunnel keeps its
// routes: apps with a rule on it stay blocked, they never go direct.
func (d *Daemon) setTunnelState(name, state string, dur time.Duration) error {
	d.mu.Lock()
	_, ok := d.cfg.Tunnels[name]
	d.mu.Unlock()
	if !ok {
		return fmt.Errorf("no tunnel %q", name)
	}
	switch state {
	case "on", "off":
		woke := d.stopSleep(name)
		cfg := d.fileCfg()
		ft := cfg.Tunnels[name]
		if ft.Disabled == (state == "off") {
			if woke {
				return d.reloadNow()
			}
			return nil
		}
		ts := make(map[string]config.Tunnel, len(cfg.Tunnels))
		for n, x := range cfg.Tunnels {
			ts[n] = x
		}
		ft.Disabled = state == "off"
		ts[name] = ft
		cfg.Tunnels = ts
		raw, err := cfg.Encode()
		if err != nil {
			return err
		}
		_, err = d.saveConfig(raw, "")
		return err
	case "sleep":
		if d.fileCfg().Tunnels[name].Disabled {
			return fmt.Errorf("tunnel %q is off already", name)
		}
		if dur < minSleep || dur > maxSleep {
			return fmt.Errorf("sleep: between 1 minute and 24 hours")
		}
		d.stopSleep(name)
		d.sleepMu.Lock()
		if d.sleepers == nil {
			d.sleepers = map[string]*sleeper{}
		}
		d.sleepers[name] = &sleeper{until: time.Now().Add(dur), timer: time.AfterFunc(dur, func() {
			if d.stopSleep(name) {
				if err := d.reloadNow(); err != nil {
					d.Log.Warn("tunnel could not wake up", "tunnel", name, "err", err)
				}
			}
		})}
		d.sleepMu.Unlock()
		if err := d.reloadNow(); err != nil {
			d.stopSleep(name)
			return err
		}
		return nil
	}
	return fmt.Errorf("state: on, off or sleep")
}
