package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/api"
	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/Bob-Nixkoenner/the_shunt/internal/defense"
	"github.com/Bob-Nixkoenner/the_shunt/internal/dnsproxy"
	"github.com/Bob-Nixkoenner/the_shunt/internal/netdetect"
)

// defenseState is everything the daemon keeps for the defense (package
// internal/defense). Events, bans and network keys stay on this machine;
// logs only ever name the network class, never an SSID, MAC or address.
type defenseState struct {
	m       *defense.Manager
	sensors *defense.Sensors
	iface   atomic.Value // string: uplink the decoys bind to

	mu       sync.Mutex
	tableOn  bool  // nft table shunt_defense is installed (Linux)
	portsSet []int // decoy ports last pushed to the nft set
	needPush bool  // main table was replaced: push the ports again
	never    []netip.Prefix
	logStop  func() // stops the packet log reader
	lastEnv  string // class/key/enabled the sensors run for
}

func (d *Daemon) defIface() string {
	s, _ := d.def.iface.Load().(string)
	return s
}

// startDefense creates the manager; the config is applied by reload.
func (d *Daemon) startDefense(ctx context.Context) {
	opts := d.defenseOptions()
	d.def.m = defense.NewManager(d.Log, opts...)
	d.def.sensors = d.newSensors()
	d.def.iface.Store("")
	go func() {
		<-ctx.Done()
		d.stopDefense()
	}()
	go d.defenseLoops(ctx)
}

// defenseNet starts defenseNetwork in the background (it takes d.mu).
func (d *Daemon) defenseNet(info netdetect.Info) { go d.defenseNetwork(info) }

func (d *Daemon) stopDefense() {
	if d.def.sensors != nil {
		d.def.sensors.Stop()
	}
	if d.def.m != nil {
		d.def.m.Close()
	}
	d.defenseTable(false)
}

// defenseApply hands a (re)loaded config to the manager. Called by reload
// with d.mu held.
func (d *Daemon) defenseApply(c *config.Config) {
	if d.def.m == nil {
		return
	}
	cfg := c.DefenseConfig()
	d.def.m.Configure(cfg)
	d.defenseTable(cfg.Enabled)
	d.def.mu.Lock()
	d.def.needPush = true
	d.def.mu.Unlock()
}

// defNetKey is the local network identifier: a hash, only ever kept in memory.
func defNetKey(info netdetect.Info) string {
	h := sha256.Sum256([]byte(info.Key()))
	return hex.EncodeToString(h[:8])
}

// defenseNetwork tells the defense where the machine is now. Only the class
// is logged.
func (d *Daemon) defenseNetwork(info netdetect.Info) {
	if d.def.m == nil {
		return
	}
	d.mu.Lock()
	cfg := d.cfg
	d.mu.Unlock()
	if cfg == nil {
		return
	}
	class := cfg.NetClass(info)
	d.def.iface.Store(info.Iface)
	d.def.m.SetNetwork(defNetKey(info), class)
	env := defense.Env{Iface: info.Iface, SSID: info.SSID, GatewayIP: info.GatewayIP, GatewayMAC: info.GatewayMAC}
	var never []netip.Prefix
	if a, err := netip.ParseAddr(info.GatewayIP); err == nil {
		never = append(never, netip.PrefixFrom(a, a.BitLen()))
	}
	for _, s := range dnsproxy.SystemUpstreams() {
		env.DNS = append(env.DNS, s.Addr.String())
		never = append(never, netip.PrefixFrom(s.Addr.Addr(), s.Addr.Addr().BitLen()))
	}
	d.def.m.SetNever(never)
	d.defenseNever(never)
	on := cfg.DefenseConfig().Enabled
	cur := defNetKey(info) + "|" + string(class) + "|" + strconv.FormatBool(on)
	d.def.mu.Lock()
	same := cur == d.def.lastEnv
	d.def.lastEnv = cur
	d.def.mu.Unlock()
	if same {
		return
	}
	if on {
		d.Log.Info("defense: network joined", "class", class)
		d.def.sensors.SetEnv(env)
	} else {
		d.def.sensors.Stop()
	}
}

// defenseReport adds a passive finding from the daemon itself.
func (d *Daemon) defenseReport(ev defense.Event) {
	if d.def.m != nil {
		d.def.m.Report(ev)
	}
}

// defenseBrief is the short form for the status call (nil while off).
func (d *Daemon) defenseBrief() *api.DefenseBrief {
	if d.def.m == nil {
		return nil
	}
	s := d.def.m.Status()
	if !s.Enabled {
		return nil
	}
	return &api.DefenseBrief{Heat: s.Heat, Level: s.Level, Class: s.Class}
}

// defenseStatus is GET /v1/defense.
func (d *Daemon) defenseStatus() defense.Status {
	if d.def.m == nil {
		return defense.Status{Class: defense.ClassPublic, Level: defense.LevelQuiet, Config: defense.DefaultConfig(),
			Unsupported: "the defense is not running"}
	}
	s := d.def.m.Status()
	s.Unsupported = defenseUnsupported
	return s
}

// saveDefenseConfig writes the [defense] section into the config file; the
// reload that follows applies it.
func (d *Daemon) saveDefenseConfig(cfg defense.Config) error {
	d.mu.Lock()
	cp := *d.cfg
	d.mu.Unlock()
	cp.Defense = &cfg
	raw, err := cp.Encode()
	if err != nil {
		return err
	}
	_, err = d.saveConfig(raw, "")
	return err
}

func (d *Daemon) defenseRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/defense", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, d.defenseStatus())
	})
	mux.HandleFunc("GET /v1/defense/events", func(w http.ResponseWriter, r *http.Request) {
		since, _ := strconv.ParseUint(r.URL.Query().Get("since"), 10, 64)
		if d.def.m == nil {
			writeJSON(w, http.StatusOK, defense.EventsResponse{Events: []defense.Event{}})
			return
		}
		writeJSON(w, http.StatusOK, d.def.m.Events(since))
	})
	mux.HandleFunc("POST /v1/defense/config", func(w http.ResponseWriter, r *http.Request) {
		if err := d.authorize(r.Context(), peerOf(r.Context())); err != nil {
			writeErr(w, http.StatusForbidden, err)
			return
		}
		var cfg defense.Config
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&cfg); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		if err := d.saveDefenseConfig(cfg); err != nil {
			writeErr(w, http.StatusUnprocessableEntity, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /v1/defense/unban", func(w http.ResponseWriter, r *http.Request) {
		// lifting a block weakens the protection: managing
		if err := d.authorize(r.Context(), peerOf(r.Context())); err != nil {
			writeErr(w, http.StatusForbidden, err)
			return
		}
		var req api.DefenseUnban
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		if req.Src != "" {
			if _, err := netip.ParseAddr(strings.TrimSpace(req.Src)); err != nil {
				writeErr(w, http.StatusBadRequest, err)
				return
			}
		}
		if d.def.m != nil {
			d.def.m.Unban(strings.TrimSpace(req.Src))
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

// defenseCacheDir holds the reputation lists and the evil-twin memory.
func (d *Daemon) defenseDir() string {
	return filepath.Join(filepath.Dir(d.filterDir()), "defense")
}

// defenseLoops runs the reputation updater (twice a day, only while the
// feature is on) and the platform's background work.
func (d *Daemon) defenseLoops(ctx context.Context) {
	up := &defense.Updater{Rep: d.def.m.Reputation(), Dir: d.defenseDir(), Client: d.downloadClient()}
	go func() {
		tk := time.NewTicker(5 * time.Second)
		defer tk.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tk.C:
				d.defensePushPorts()
			}
		}
	}()
	t := time.NewTimer(20 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if d.def.m.Watching(defense.FeatReputation) {
			up.Client = d.downloadClient()
			rctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			if err := up.Refresh(rctx, defense.SourcesFor(d.def.m.Status().Config.ReputationSources)); err != nil {
				d.Log.Debug("defense: reputation lists", "err", err)
			}
			cancel()
			t.Reset(12 * time.Hour)
		} else {
			t.Reset(time.Minute)
		}
	}
}
