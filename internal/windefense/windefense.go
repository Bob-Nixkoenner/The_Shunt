// Package windefense connects the defense module (internal/defense) to the
// Windows service. Step 1 is a watcher like the Android one: it listens to
// what the netstack sees (DNS queries and answers, new connections per
// program), compares destinations with the reputation lists and reports.
// It blocks nothing and opens no ports; bans and decoys need WFP and come
// in a later step. No Windows-only code: tested on Linux.
package windefense

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/api"
	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/Bob-Nixkoenner/the_shunt/internal/defense"
	"github.com/Bob-Nixkoenner/the_shunt/internal/netdetect"
)

// Features that work on Windows in this step; the others stay off and
// cannot be switched on (the status says so).
var Features = []string{defense.FeatDNSTunnel, defense.FeatReputation, defense.FeatFirstSeen, defense.FeatBeacon}

// Unsupported is shown in the status next to the features that do work.
const Unsupported = "Windows watches DNS, connections and reputation lists for now; decoys, blocking, ARP/DHCP and the certificate check follow"

func noListen(int) (net.Listener, error) { return nil, errors.New("no decoy listeners on Windows yet") }

// Runner owns the manager and feeds it.
type Runner struct {
	M      *defense.Manager
	dir    string
	log    *slog.Logger
	client func() *http.Client

	mu    sync.Mutex
	cfg   *config.Config
	info  netdetect.Info
	loops sync.Once
}

// New creates the manager. dir holds the reports, the first-contact memory
// and the list cache (created as needed). client downloads the reputation
// lists (may be nil).
func New(dir string, log *slog.Logger, client func() *http.Client) *Runner {
	if log == nil {
		log = slog.Default()
	}
	opts := []defense.Option{defense.WithListen(noListen), defense.WithStartGrace(30 * time.Second)}
	if dir != "" {
		opts = append(opts,
			defense.WithReportFile(filepath.Join(dir, "reports.json")),
			defense.WithFirstSeenFile(filepath.Join(dir, "firstseen.json")))
	}
	r := &Runner{dir: dir, log: log, client: client}
	r.M = defense.NewManager(log, opts...)
	return r
}

// Limit reduces a config to what runs here: unsupported features lose Watch
// and Block, supported ones keep Watch only (nothing is blocked), decoys
// and evidence capture are off.
func Limit(cfg defense.Config) defense.Config {
	f := map[string]defense.Feature{}
	for _, n := range defense.AllFeatures {
		f[n] = defense.Feature{}
	}
	for _, n := range Features {
		f[n] = defense.Feature{Watch: cfg.Features[n].Watch}
	}
	cfg.Features = f
	cfg.DecoyPorts = nil
	return cfg
}

// Apply is called with every config that takes effect.
func (r *Runner) Apply(c *config.Config) {
	r.mu.Lock()
	r.cfg = c
	info := r.info
	r.mu.Unlock()
	r.M.Configure(Limit(c.DefenseConfig()))
	r.Network(info)
}

// NetKey is the local network identifier: a hash, kept in memory only.
// Like on Linux it ignores the gateway's MAC.
func NetKey(info netdetect.Info) string {
	h := sha256.Sum256([]byte(info.Iface + "|" + info.SSID + "|" + info.GatewayIP))
	return hex.EncodeToString(h[:8])
}

// Network tells the defense where the machine is now. Only the class is
// logged, never the name of the network.
func (r *Runner) Network(info netdetect.Info) {
	r.mu.Lock()
	r.info = info
	c := r.cfg
	r.mu.Unlock()
	if c == nil || info.Iface == "" {
		return
	}
	class := r.class(c, info)
	r.M.SetNetwork(NetKey(info), class)
	mode := "off"
	profile := ""
	if n := c.MatchNetwork(info.SSID, info.GatewayMAC); n != nil {
		profile = n.Name
	}
	if m, _ := c.InboundFor(profile); m != "" {
		mode = m
	}
	r.M.SetExposure(defense.Exposure{V4: info.PublicV4, V6: info.PublicV6, Inbound: mode})
	r.log.Info("defense: network", "class", class)
}

// class is the config's class of the network; without a matching
// [[network]] profile the system's rating gives a hint (only "public" makes
// it stricter, nothing ever becomes safe by itself).
func (r *Runner) class(c *config.Config, info netdetect.Info) defense.Class {
	if c.MatchNetwork(info.SSID, info.GatewayMAC) == nil && info.OSProfile != "" {
		return defense.Class(netdetect.ClassHint(info.OSProfile)).Normalize()
	}
	return c.NetClass(info)
}

// Start runs the background work (reputation lists, twice a day, only while
// the feature is on). Safe to call more than once.
func (r *Runner) Start(ctx context.Context) {
	r.loops.Do(func() {
		go defense.GuardLoop(ctx, r.log, "reputation updater", func() { r.updateLoop(ctx) })
		go func() { <-ctx.Done(); r.Close() }()
	})
}

func (r *Runner) updateLoop(ctx context.Context) {
	up := &defense.Updater{Rep: r.M.Reputation(), Dir: r.dir}
	t := time.NewTimer(20 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if r.M.Watching(defense.FeatReputation) {
			if r.client != nil {
				up.Client = r.client()
			}
			st := r.M.Status().Config
			rctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			if err := up.Refresh(rctx, defense.SourcesFor(st.ReputationSources, st.ReputationOff)); err != nil {
				r.log.Debug("defense: reputation lists", "err", err)
			}
			cancel()
			t.Reset(12 * time.Hour)
		} else {
			t.Reset(time.Minute)
		}
	}
}

// Close stops the manager.
func (r *Runner) Close() { r.M.Close() }

// Status is GET /v1/defense.
func (r *Runner) Status() defense.Status {
	s := r.M.Status()
	s.Unsupported = Unsupported
	return s
}

// Brief is the short form for the status call (nil while off).
func (r *Runner) Brief() *api.DefenseBrief {
	s := r.M.Status()
	if !s.Enabled {
		return nil
	}
	return &api.DefenseBrief{Heat: s.Heat, Level: s.Level, Class: s.Class, Exposed: s.Exposed.Any(), ExposedInbound: s.Exposed.Inbound}
}

// SaveConfig writes cfg as the [defense] section; the reload applies it.
// save gets the whole new config text (the Manager's Save of winsvc).
func SaveConfig(cur *config.Config, cfg defense.Config) ([]byte, error) {
	cp := *cur
	cp.Defense = &cfg
	raw, err := cp.Encode()
	if err != nil {
		return nil, fmt.Errorf("defense config: %w", err)
	}
	return raw, nil
}
