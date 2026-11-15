// Package windefense connects the defense module (internal/defense) to the
// Windows service. It watches what the netstack sees (DNS queries and
// answers, new connections per program), compares destinations with the
// reputation lists, runs decoys on the uplink and blocks sources through
// WFP (wfp.Banner, behind the Firewall interface). No Windows-only code:
// tested on Linux with a fake firewall.
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
	"net/netip"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/api"
	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/Bob-Nixkoenner/the_shunt/internal/defense"
	"github.com/Bob-Nixkoenner/the_shunt/internal/netdetect"
	"github.com/Bob-Nixkoenner/the_shunt/internal/winsplit/wfp"
)

// Features that work on Windows; the others stay off and cannot be
// switched on (the status says so).
var Features = []string{defense.FeatDNSTunnel, defense.FeatReputation, defense.FeatFirstSeen, defense.FeatBeacon,
	defense.FeatDecoy, defense.FeatScan, defense.FeatBrute}

// BlockFeatures may block on Windows. Their only trigger is an inbound hit
// on a decoy (outgoing connections to listed addresses are reported, never
// blocked), so Limit lets their Block switch through only while decoys can
// run and the firewall filters are in place.
var BlockFeatures = []string{defense.FeatReputation, defense.FeatScan, defense.FeatBrute}

// Unsupported is shown in the status next to the features that do work.
const Unsupported = "Windows: tarpit, fake logins, ARP/DHCP, Wi-Fi twin and the certificate check follow"

// unsupportedNoBlock is added while the firewall filters are missing.
const unsupportedNoBlock = "; blocking is off (the firewall filters for bans are not in place)"

// Firewall installs the bans (wfp.Banner on Windows). Every call may fail;
// a failed Add means: no ban, logged, the entry is dropped.
type Firewall interface {
	SetNever([]netip.Prefix) error
	Add(netip.Prefix) error
	Remove(netip.Prefix) error
	Clear() error
}

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

	fwMu    sync.Mutex // serialises firewall calls; never held with mu
	fw      Firewall
	fwOK    bool // never-list in place: bans possible
	never   map[string][]netip.Prefix
	neverOn string // the list last handed to the firewall
}

// New creates the manager. dir holds the reports, the first-contact memory
// and the list cache (created as needed). client downloads the reputation
// lists (may be nil). listen opens decoy listeners (nil: no decoys).
func New(dir string, log *slog.Logger, client func() *http.Client, listen defense.ListenFunc) *Runner {
	if log == nil {
		log = slog.Default()
	}
	if listen == nil {
		listen = noListen
	}
	r := &Runner{dir: dir, log: log, client: client, never: map[string][]netip.Prefix{}}
	opts := []defense.Option{defense.WithListen(listen), defense.WithStartGrace(30 * time.Second),
		defense.WithBanHooks(r.onBan, r.onUnban), defense.WithMaxBans(wfp.BanMaxBans)}
	if dir != "" {
		opts = append(opts,
			defense.WithReportFile(filepath.Join(dir, "reports.json")),
			defense.WithFirstSeenFile(filepath.Join(dir, "firstseen.json")),
			defense.WithDecoySecret(filepath.Join(dir, "decoy-secret")))
	}
	r.M = defense.NewManager(log, opts...)
	return r
}

func noListen(int) (net.Listener, error) { return nil, errors.New("no decoy listeners") }

// Limit reduces a config to what runs here: unsupported features lose Watch
// and Block. The Block switches of BlockFeatures stay only when canBlock
// (firewall filters in place) and decoys can trigger them; otherwise the
// unsafe-network override is off too, so nothing believes it blocks.
func Limit(cfg defense.Config, canBlock bool) defense.Config {
	f := map[string]defense.Feature{}
	for _, n := range defense.AllFeatures {
		f[n] = defense.Feature{}
	}
	for _, n := range Features {
		f[n] = defense.Feature{Watch: cfg.Features[n].Watch}
	}
	trigger := canBlock && cfg.Features[defense.FeatDecoy].Watch && len(cfg.DecoyPorts) > 0
	if trigger {
		for _, n := range BlockFeatures {
			if f[n].Watch {
				f[n] = defense.Feature{Watch: true, Block: cfg.Features[n].Block}
			}
		}
	} else {
		off := false
		cfg.UnsafeBlock = &off
	}
	cfg.Features = f
	return cfg
}

// UseFirewall hands the ban filters over (nil: none, nothing is blocked).
// The current never-list goes in first; bans the table already holds are
// installed.
func (r *Runner) UseFirewall(fw Firewall) {
	r.fwMu.Lock()
	r.fw, r.fwOK, r.neverOn = fw, false, ""
	r.fwMu.Unlock()
	r.pushNever()
	for _, b := range r.M.Status().Bans {
		r.onBan(b)
	}
	r.reconfigure()
}

// CanBlock reports whether bans are put into effect.
func (r *Runner) CanBlock() bool {
	r.fwMu.Lock()
	defer r.fwMu.Unlock()
	return r.fw != nil && r.fwOK
}

func (r *Runner) onBan(b defense.Ban) {
	defense.Guard(r.log, "defense ban", func() {
		p, err := wfp.BanPrefix(b.Src)
		if err == nil {
			r.fwMu.Lock()
			switch {
			case r.fw == nil:
				err = errors.New("no firewall filters")
			case !r.fwOK:
				err = errors.New("never-list not in place")
			default:
				err = r.fw.Add(p)
			}
			r.fwMu.Unlock()
		}
		if err != nil {
			// no ban rather than a wrong one: the entry goes again
			r.log.Warn("defense: could not block a source (not blocked)", "err", err)
			go r.M.Drop(b.Src, "not_enforced")
		}
	})
}

func (r *Runner) onUnban(b defense.Ban) {
	defense.Guard(r.log, "defense unban", func() {
		p, err := wfp.BanPrefix(b.Src)
		if err != nil {
			return
		}
		r.fwMu.Lock()
		if r.fw != nil {
			err = r.fw.Remove(p)
		}
		r.fwMu.Unlock()
		if err != nil {
			r.log.Warn("defense: could not lift a block", "err", err)
		}
	})
}

// LiftAll is the emergency switch: every ban goes, in the table and in the
// firewall (also what the table may have lost). Called when the defense is
// switched off, on a stop and from the API.
func (r *Runner) LiftAll(why string) {
	r.M.Drop("", why)
	r.fwMu.Lock()
	var err error
	if r.fw != nil {
		err = r.fw.Clear()
	}
	r.fwMu.Unlock()
	if err != nil {
		r.log.Warn("defense: lifting all blocks", "err", err)
	}
}

// Never-list parts.
const (
	NeverNet = "net" // gateway
	NeverDNS = "dns" // DNS servers of the network
	NeverTun = "tun" // tunnel endpoints
)

// SetNever replaces one part of the automatic never-block list and hands
// the whole list to the manager and the firewall.
func (r *Runner) SetNever(part string, p []netip.Prefix) {
	r.mu.Lock()
	r.never[part] = append([]netip.Prefix(nil), p...)
	r.mu.Unlock()
	r.pushNever()
}

// neverAll is the automatic list plus the configured one (as far as it
// fits), single addresses as /32 or /128; haveGW says whether the
// gateway is on it (no bans without).
func (r *Runner) neverAll() (auto, all []netip.Prefix, haveGW bool) {
	r.mu.Lock()
	haveGW = len(r.never[NeverNet]) > 0
	parts := make([]string, 0, len(r.never))
	for k := range r.never {
		parts = append(parts, k)
	}
	sort.Strings(parts)
	for _, k := range parts {
		auto = append(auto, r.never[k]...)
	}
	var conf []string
	if r.cfg != nil {
		conf = r.cfg.DefenseConfig().Never
	}
	r.mu.Unlock()
	all = append([]netip.Prefix(nil), auto...)
	for _, p := range defense.ParsePrefixes(conf) {
		if len(all) >= wfp.BanMaxNever {
			break
		}
		all = append(all, p)
	}
	return auto, all, haveGW
}

var errNoGateway = errors.New("gateway not known yet")

func (r *Runner) pushNever() {
	auto, all, haveGW := r.neverAll()
	r.M.SetNever(auto)
	norm, err := wfp.NormNever(all)
	if err == nil && !haveGW {
		// the gateway is not known yet: it could be blocked, so nothing is
		err = errNoGateway
	}
	key := fmt.Sprint(norm)
	r.fwMu.Lock()
	if r.fw == nil || (r.fwOK && key == r.neverOn) {
		r.fwMu.Unlock()
		return
	}
	if err == nil {
		err = r.fw.SetNever(norm)
	}
	was := r.fwOK
	r.fwOK = err == nil
	if r.fwOK {
		r.neverOn = key
	}
	r.fwMu.Unlock()
	switch {
	case errors.Is(err, errNoGateway):
		r.log.Debug("defense: no blocking until the gateway is known")
	case err != nil:
		r.log.Warn("defense: never-block list not in place, blocking is off", "err", err)
	}
	if was != (err == nil) {
		r.reconfigure()
	}
}

// reconfigure applies the last config again (the block switches follow
// whether the firewall can block).
func (r *Runner) reconfigure() {
	r.mu.Lock()
	c := r.cfg
	r.mu.Unlock()
	if c == nil {
		return
	}
	r.M.Configure(Limit(c.DefenseConfig(), r.CanBlock()))
	if !r.CanBlock() {
		r.LiftAll("blocking_off")
	}
}

// TunnelPeers turns tunnel endpoints ("192.0.2.1:51820", "[2001:db8::1]:51820",
// "vpn.example.net:51820", a bare address) into never-block entries; names
// are resolved with lookup (nil: skipped). At most 64 entries.
func TunnelPeers(ctx context.Context, endpoints []string, lookup func(ctx context.Context, host string) ([]netip.Addr, error)) []netip.Prefix {
	seen := map[netip.Addr]bool{}
	var out []netip.Prefix
	add := func(a netip.Addr) {
		a = a.Unmap().WithZone("")
		if !a.IsValid() || a.IsUnspecified() || a.IsLoopback() || seen[a] || len(out) >= 64 {
			return
		}
		seen[a] = true
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	for _, e := range endpoints {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		host := e
		if h, _, err := net.SplitHostPort(e); err == nil {
			host = h
		}
		if a, err := netip.ParseAddr(host); err == nil {
			add(a)
			continue
		}
		if lookup == nil || strings.ContainsAny(host, " /") {
			continue
		}
		as, err := lookup(ctx, host)
		if err != nil {
			continue
		}
		for _, a := range as {
			add(a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr().Less(out[j].Addr()) })
	return out
}

// Apply is called with every config that takes effect.
func (r *Runner) Apply(c *config.Config) {
	r.mu.Lock()
	r.cfg = c
	info := r.info
	r.mu.Unlock()
	r.M.Configure(Limit(c.DefenseConfig(), r.CanBlock()))
	if !c.DefenseConfig().Enabled || !r.CanBlock() {
		r.LiftAll("defense_off") // emergency switch: nothing stays blocked
	}
	r.pushNever() // the configured never entries may have changed
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
	class := c.NetClass(info)
	var gw []netip.Prefix
	if a, err := netip.ParseAddr(info.GatewayIP); err == nil {
		a = a.Unmap()
		gw = append(gw, netip.PrefixFrom(a, a.BitLen()))
	}
	r.SetNever(NeverNet, gw)
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

// Close stops the manager and lifts every ban (the firewall itself is
// closed by its owner).
func (r *Runner) Close() {
	r.LiftAll("stopped")
	r.M.Close()
}

// Ban blocks src by hand (POST /v1/defense/ban).
func (r *Runner) Ban(src string) error {
	if !r.CanBlock() {
		return ErrNoBlocking
	}
	return r.M.Ban(src)
}

// ErrNoBlocking: the firewall filters for bans are not in place.
var ErrNoBlocking = errors.New("blocking is not available: the firewall filters for bans are not in place")

// Status is GET /v1/defense.
func (r *Runner) Status() defense.Status {
	s := r.M.Status()
	s.Unsupported = Unsupported
	if !r.CanBlock() {
		s.Unsupported += unsupportedNoBlock
	}
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
