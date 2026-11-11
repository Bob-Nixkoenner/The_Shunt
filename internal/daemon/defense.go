package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
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

	loops       atomic.Bool   // background loops were started
	tlsBusy     atomic.Bool   // a certificate check is running
	outsideBusy atomic.Bool   // an outside check is running
	tlsSoon     chan struct{} // a new network: check again soon
}

func (d *Daemon) defIface() string {
	s, _ := d.def.iface.Load().(string)
	return s
}

// startDefense creates the manager; the config is applied by reload.
func (d *Daemon) startDefense(ctx context.Context) {
	opts := append(d.defenseOptions(), defense.WithReportFile(filepath.Join(d.defenseDir(), "reports.json")),
		defense.WithFirstSeenFile(filepath.Join(d.defenseDir(), "firstseen.json")),
		defense.WithSSHHostKey(filepath.Join(d.defenseDir(), "ssh_host_ed25519_key")))
	d.def.m = defense.NewManager(d.Log, opts...)
	d.def.sensors = d.newSensors()
	d.def.iface.Store("")
	d.def.tlsSoon = make(chan struct{}, 1)
	go func() {
		<-ctx.Done()
		d.stopDefense()
	}()
}

// startDefenseLoops starts the background work; only called once the daemon
// has started (config applied, plan in place).
func (d *Daemon) startDefenseLoops(ctx context.Context) {
	if d.def.m == nil {
		return
	}
	if !d.def.loops.CompareAndSwap(false, true) {
		return
	}
	go d.defenseLoops(ctx)
	go d.defenseConnLoop(ctx)
	go d.defenseTLSLoop(ctx)
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
// It uses interface, SSID and gateway address but NOT the gateway's MAC: a
// new MAC behind the same address is a finding (arp), not a new network.
func defNetKey(info netdetect.Info) string {
	h := sha256.Sum256([]byte(info.Iface + "|" + info.SSID + "|" + info.GatewayIP))
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
	profile := ""
	if n := cfg.MatchNetwork(info.SSID, info.GatewayMAC); n != nil {
		profile = n.Name
	}
	inMode, _ := cfg.InboundFor(profile)
	if inMode == "" {
		inMode = "off"
	}
	d.def.m.SetExposure(defense.Exposure{V4: info.PublicV4, V6: info.PublicV6, Inbound: inMode})
	env := defense.Env{Iface: info.Iface, SSID: info.SSID, GatewayIP: info.GatewayIP, GatewayMAC: info.GatewayMAC}
	var never []netip.Prefix
	if a, err := netip.ParseAddr(info.GatewayIP); err == nil {
		never = append(never, netip.PrefixFrom(a, a.BitLen()))
	}
	for _, s := range dnsproxy.SystemUpstreams() {
		env.DNS = append(env.DNS, s.Addr.String())
		never = append(never, netip.PrefixFrom(s.Addr.Addr(), s.Addr.Addr().BitLen()))
	}
	quiet := true
	if n := cfg.MatchNetwork(info.SSID, info.GatewayMAC); n != nil {
		quiet = cfg.QuietFor(n.Name)
	} else {
		quiet = cfg.QuietFor("")
	}
	mode := cfg.DefenseConfig().DHCPProbe
	env.DHCPProbe = defense.ProbeAllowed(mode, class, quiet)
	env.DNSProbe = defense.ProbeAllowed(cfg.DefenseConfig().DNSProbe, class, quiet)
	d.def.m.SetNever(never)
	d.defenseNever(never)
	on := cfg.DefenseConfig().Enabled
	cur := defNetKey(info) + "|" + string(class) + "|" + strconv.FormatBool(on) + "|" + strconv.FormatBool(env.DHCPProbe) + strconv.FormatBool(env.DNSProbe)
	d.def.mu.Lock()
	same := cur == d.def.lastEnv
	d.def.lastEnv = cur
	d.def.mu.Unlock()
	if same {
		return
	}
	if on {
		d.Log.Info("defense: network joined", "class", class)
		select {
		case d.def.tlsSoon <- struct{}{}:
		default:
		}
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
	return &api.DefenseBrief{Heat: s.Heat, Level: s.Level, Class: s.Class, Exposed: s.Exposed.Any(), ExposedInbound: s.Exposed.Inbound}
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
		if src := r.URL.Query().Get("src"); src != "" {
			if _, err := netip.ParseAddr(src); err != nil {
				writeErr(w, http.StatusBadRequest, fmt.Errorf("src: not an IP address"))
				return
			}
			writeJSON(w, http.StatusOK, d.def.m.EventsFor(src))
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
	mux.HandleFunc("GET /v1/defense/reports", func(w http.ResponseWriter, r *http.Request) {
		if d.def.m == nil {
			writeJSON(w, http.StatusOK, defense.ReportsResponse{Reports: []defense.NetReport{}})
			return
		}
		writeJSON(w, http.StatusOK, d.def.m.Reports(r.URL.Query().Get("export") == "1"))
	})
	mux.HandleFunc("POST /v1/defense/ban", func(w http.ResponseWriter, r *http.Request) {
		if err := d.authorize(r.Context(), peerOf(r.Context())); err != nil {
			writeErr(w, http.StatusForbidden, err)
			return
		}
		var req api.DefenseUnban
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		if d.def.m == nil {
			writeErr(w, http.StatusConflict, fmt.Errorf("defense is not available"))
			return
		}
		if err := d.def.m.Ban(req.Src); err != nil {
			code := http.StatusBadRequest
			if errors.Is(err, defense.ErrNeverBan) {
				code = http.StatusConflict
			}
			writeErr(w, code, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /v1/defense/outside-scan", func(w http.ResponseWriter, r *http.Request) {
		// asks a server of the user's own to connect back: managing
		if err := d.authorize(r.Context(), peerOf(r.Context())); err != nil {
			writeErr(w, http.StatusForbidden, err)
			return
		}
		res, err := d.outsideScan(r.Context(), d.outsideHTTP)
		if err != nil {
			code := http.StatusConflict
			if errors.Is(err, errOutsideBusy) {
				code = http.StatusTooManyRequests
			}
			writeErr(w, code, err)
			return
		}
		writeJSON(w, http.StatusOK, res)
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
		if req.Src != "" { // an address, or a range the defense blocked as a whole
			src := strings.TrimSpace(req.Src)
			if _, err := netip.ParseAddr(src); err != nil {
				if _, err2 := netip.ParsePrefix(src); err2 != nil {
					writeErr(w, http.StatusBadRequest, err)
					return
				}
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
			if err := up.Refresh(rctx, defense.SourcesFor(d.def.m.Status().Config.ReputationSources, d.def.m.Status().Config.ReputationOff)); err != nil {
				d.Log.Debug("defense: reputation lists", "err", err)
			}
			cancel()
			t.Reset(12 * time.Hour)
		} else {
			t.Reset(time.Minute)
		}
	}
}

var errOutsideBusy = errors.New("an outside check is already running")

// outsideScan runs the outside check against the configured server (only
// for the families the uplink has a public address in) and records it.
func (d *Daemon) outsideScan(ctx context.Context, clientFor func(string) *http.Client) (defense.OutsideResult, error) {
	if d.def.m == nil {
		return defense.OutsideResult{}, errors.New("defense is not available")
	}
	if !d.def.outsideBusy.CompareAndSwap(false, true) {
		return defense.OutsideResult{}, errOutsideBusy
	}
	defer d.def.outsideBusy.Store(false)
	st := d.def.m.Status()
	res, err := defense.OutsideScan(ctx, st.Config.OutsideScan, st.Exposed, clientFor, ownAddr)
	if err != nil {
		return res, err
	}
	d.def.m.SetOutside(res)
	return res, nil
}

// ownAddr reports whether a is an address of one of this machine's interfaces.
func ownAddr(a netip.Addr) bool {
	as, _ := net.InterfaceAddrs()
	for _, x := range as {
		if n, ok := x.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP); ok && ip.Unmap() == a.Unmap() {
				return true
			}
		}
	}
	return false
}
