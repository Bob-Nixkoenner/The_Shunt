// Package winsvc is the control API of the Windows service: the same
// /v1 JSON API as shuntd on Linux (internal/api types), served from the
// splitstack engine, so the CLI and the web UI work unchanged. It has no
// Windows-only code and is tested on Linux.
package winsvc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/api"
	"github.com/Bob-Nixkoenner/the_shunt/internal/blocklist"
	"github.com/Bob-Nixkoenner/the_shunt/internal/dnsproxy"
	"github.com/Bob-Nixkoenner/the_shunt/internal/health"
	"github.com/Bob-Nixkoenner/the_shunt/internal/netdetect"
	"github.com/Bob-Nixkoenner/the_shunt/internal/stats"
	"github.com/Bob-Nixkoenner/the_shunt/internal/tunnel"
)

// Core is what the API needs from the running engine (*splitstack.Engine).
type Core interface {
	Status() string
	// History returns stats.History as JSON for a range name.
	History(rng string) string
	SetPanic(on bool)
	Pass(d time.Duration) time.Time
	// ProbeRoute runs the leak-test probe through one route (probe.Result JSON).
	ProbeRoute(ctx context.Context, route string) ([]byte, error)
}

// Server answers /v1 requests.
type Server struct {
	Core    Core
	Version string
	// Reload re-reads the config file and applies it (POST /v1/reload).
	Reload func() error
	// Restart asks the service to stop so the service manager starts it
	// again (POST /v1/restart); nil = not supported.
	Restart func()
	// Cfg serves the config endpoints (GET/PUT /v1/config, tunnels); nil
	// leaves them out.
	Cfg *Manager
	// TorBootstrap returns the progress (0..100) of the tor.exe behind a Tor
	// tunnel; ok=false if none runs for it (may be nil).
	TorBootstrap func(tunnel string) (progress int, ok bool)
	// NetInfo describes the network the machine is connected to (may be nil).
	NetInfo func() netdetect.Info
	// Config returns the default route and the app rules of the config file
	// in effect, for the status.
	Config func() (def string, apps map[string]string)
	// Pin puts a process that was just started (suspended) into route, for
	// it and its children (POST /v1/run); nil: not supported.
	Pin func(pid int, route string) error
	// Procs lists running processes by file name with the route they were
	// started in ("" = none; GET /v1/procs). nil: empty list.
	Procs func(name string) ([]api.ProcRoute, error)
	// Warnings adds service warnings to the status (clock check); may be nil.
	Warnings func() []string
}

// engineStatus is the part of splitstack's Status JSON we map.
type engineStatus struct {
	Tunnels []struct {
		Name      string        `json:"name"`
		Type      string        `json:"type"`
		Via       string        `json:"via"`
		Up        bool          `json:"up"`
		Error     string        `json:"error"`
		Bootstrap int           `json:"bootstrap"`
		Handshake int64         `json:"handshake"`
		RX        int64         `json:"rx"`
		TX        int64         `json:"tx"`
		Health    health.Report `json:"health"`
	} `json:"tunnels"`
	Traffic  map[string]stats.Summary `json:"traffic"`
	Default  string                   `json:"default"` // default route of the network profile in effect
	Override struct {
		Panic    bool  `json:"panic"`
		PassLeft int64 `json:"pass_left"`
	} `json:"override"`
	Network    string `json:"network"`
	DNSBlocked int64  `json:"dns_blocked"`
	DNSRecent  []struct {
		Time  time.Time `json:"time"`
		Name  string    `json:"name"`
		Level string    `json:"level"`
		List  string    `json:"list"`
		Route string    `json:"route"`
	} `json:"dns_recent"`
}

// Status maps the engine's state to the API's Status.
func (s *Server) Status() (api.Status, error) {
	var es engineStatus
	if err := json.Unmarshal([]byte(s.Core.Status()), &es); err != nil {
		return api.Status{}, err
	}
	def, apps := "block", map[string]string(nil)
	if s.Cfg != nil {
		def, apps = s.Cfg.Summary()
	} else if s.Config != nil {
		def, apps = s.Config()
	}
	if es.Network != "" && es.Default != "" {
		def = es.Default // a network profile replaces daemon.default_route
	}
	st := api.Status{
		Traffic:      es.Traffic,
		DefaultRoute: def,
		Panic:        es.Override.Panic,
		PassLeft:     es.Override.PassLeft,
		Network:      es.Network,
		Version:      s.Version,
		Platform:     "windows",
		Tunnels:      []api.TunnelStatus{},
		Groups:       []api.GroupStatus{},
		Rules:        []string{},
		Routes:       []string{"direct", "block"},
	}
	if s.NetInfo != nil {
		st.NetInfo = s.NetInfo()
	}
	if s.Warnings != nil {
		st.Warnings = append(st.Warnings, s.Warnings()...)
	}
	if s.Cfg != nil {
		if def, lists, on := s.Cfg.FilterStatus(); on {
			fs := &api.DNSFilterStatus{Default: def, Routes: map[string]string{"all": def}, Lists: lists,
				Stats: dnsproxy.FilterStats{Blocked: uint64(es.DNSBlocked), ByLevel: map[string]uint64{}}}
			if lists == nil {
				fs.Lists = []blocklist.Status{}
			}
			if es.DNSBlocked > 0 {
				fs.Stats.ByLevel[def] = uint64(es.DNSBlocked)
			}
			for _, b := range es.DNSRecent {
				fs.Stats.Recent = append(fs.Stats.Recent, dnsproxy.Blocked{Time: b.Time, Name: b.Name, Level: b.Level, List: b.List, Route: b.Route})
			}
			st.DNSFilter = fs
		}
	}
	for _, t := range es.Tunnels {
		ts := api.TunnelStatus{Name: t.Name, Driver: t.Type, Up: t.Up, Error: t.Error, Via: t.Via}
		h := t.Health
		ts.Health = &h
		if t.Type == "tor" {
			// Tor has no handshake: the card shows tor's progress. The SOCKS
			// port answers long before tor is through the network, so the
			// engine's "reachable" alone is not "connected".
			b, ok := t.Bootstrap, t.Bootstrap > 0
			if s.TorBootstrap != nil {
				if v, has := s.TorBootstrap(t.Name); has {
					b, ok = v, true
				}
			}
			if !ok || b < 1 {
				b = 1 // starting
			}
			ts.Bootstrap = &b
			if b < 100 {
				ts.Health = &health.Report{State: health.Unknown, HandshakeAge: -1}
				if ts.Error == "" && t.Up {
					ts.Error = fmt.Sprintf("Tor is starting: %d %%", b)
				}
			}
			ts.Peers = []tunnel.PeerStatus{{RxBytes: t.RX, TxBytes: t.TX}}
		} else {
			ts.Peers = []tunnel.PeerStatus{{RxBytes: t.RX, TxBytes: t.TX}}
			if s.Cfg != nil {
				ts.Peers[0].Endpoint = s.Cfg.Endpoint(t.Name)
			}
			if t.Handshake > 0 {
				ts.Peers[0].LastHandshake = time.Unix(t.Handshake, 0)
			}
		}
		st.Tunnels = append(st.Tunnels, ts)
		st.Routes = append(st.Routes, "tunnel:"+t.Name)
	}
	// one line per app rule, sorted so the list doesn't jump
	for app, route := range apps {
		st.Rules = append(st.Rules, app+" -> "+route)
	}
	sort.Strings(st.Rules)
	return st, nil
}

// Handler returns the /v1 routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		st, err := s.Status()
		if err != nil {
			fail(w, http.StatusInternalServerError, err)
			return
		}
		ok(w, st)
	})
	mux.HandleFunc("GET /v1/history", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(s.Core.History(r.URL.Query().Get("range"))))
	})
	mux.HandleFunc("POST /v1/panic", func(w http.ResponseWriter, r *http.Request) {
		var req api.PanicRequest
		if !decode(w, r, &req) {
			return
		}
		s.Core.SetPanic(req.On)
		ok(w, map[string]bool{"panic": req.On})
	})
	mux.HandleFunc("POST /v1/pass", func(w http.ResponseWriter, r *http.Request) {
		var req api.PassRequest
		if !decode(w, r, &req) {
			return
		}
		if req.Minutes < 0 || req.Minutes > 60 {
			fail(w, http.StatusBadRequest, errors.New("minutes must be 0..60"))
			return
		}
		until := s.Core.Pass(time.Duration(req.Minutes) * time.Minute)
		ok(w, map[string]int64{"until": until.Unix()})
	})
	mux.HandleFunc("POST /v1/probe", func(w http.ResponseWriter, r *http.Request) {
		var req api.ProbeRequest
		if !decode(w, r, &req) {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		out, err := s.Core.ProbeRoute(ctx, req.Route)
		if err != nil {
			fail(w, http.StatusNotFound, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(out)
	})
	mux.HandleFunc("POST /v1/reload", func(w http.ResponseWriter, r *http.Request) {
		if s.Reload == nil {
			fail(w, http.StatusNotImplemented, errors.New("reload not supported"))
			return
		}
		if err := s.Reload(); err != nil {
			fail(w, http.StatusBadRequest, err)
			return
		}
		ok(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /v1/restart", func(w http.ResponseWriter, r *http.Request) {
		if s.Restart == nil {
			fail(w, http.StatusNotImplemented, errors.New("restart not supported"))
			return
		}
		ok(w, map[string]bool{"ok": true})
		go func() { time.Sleep(200 * time.Millisecond); s.Restart() }()
	})
	// Windows has no app firewall yet; the UI still asks.
	mux.HandleFunc("GET /v1/pending", func(w http.ResponseWriter, r *http.Request) { ok(w, []string{}) })
	mux.HandleFunc("GET /v1/firewall/apps", func(w http.ResponseWriter, r *http.Request) { ok(w, []string{}) })
	mux.HandleFunc("GET /v1/procs", func(w http.ResponseWriter, r *http.Request) {
		if s.Procs == nil {
			ok(w, []api.ProcRoute{})
			return
		}
		ps, err := s.Procs(r.URL.Query().Get("name"))
		if err != nil {
			fail(w, http.StatusInternalServerError, err)
			return
		}
		s.fillRoutes(ps)
		ok(w, ps)
	})
	mux.HandleFunc("POST /v1/run", func(w http.ResponseWriter, r *http.Request) {
		var req api.RunRequest
		if !decode(w, r, &req) {
			return
		}
		if s.Pin == nil || s.Cfg == nil {
			fail(w, http.StatusNotImplemented, errors.New("starting an app in a route is not supported"))
			return
		}
		route, err := s.Cfg.CheckRoute(req.Route)
		if err != nil || req.PID <= 0 {
			fail(w, http.StatusBadRequest, fmt.Errorf("run: %v (pid %d)", err, req.PID))
			return
		}
		if err := s.Pin(req.PID, route); err != nil {
			fail(w, http.StatusBadRequest, err)
			return
		}
		ok(w, map[string]string{"route": route})
	})
	if s.Cfg != nil {
		s.configRoutes(mux)
	}
	return mux
}

func (s *Server) configRoutes(mux *http.ServeMux) {
	m := s.Cfg
	mux.HandleFunc("GET /v1/config", func(w http.ResponseWriter, r *http.Request) {
		v, err := m.View()
		if err != nil {
			fail(w, http.StatusInternalServerError, err)
			return
		}
		ok(w, v)
	})
	mux.HandleFunc("POST /v1/config/check", func(w http.ResponseWriter, r *http.Request) {
		var req api.ConfigSave
		if !decode(w, r, &req) {
			return
		}
		raw, err := m.RawOf(req)
		var warn []string
		if err == nil {
			warn, err = m.Check(raw)
		}
		if err != nil {
			ok(w, api.CheckResult{Error: err.Error()})
			return
		}
		ok(w, api.CheckResult{OK: true, Warnings: warn})
	})
	mux.HandleFunc("PUT /v1/config", func(w http.ResponseWriter, r *http.Request) {
		var req api.ConfigSave
		if !decode(w, r, &req) {
			return
		}
		raw, err := m.RawOf(req)
		if err != nil {
			fail(w, http.StatusBadRequest, err)
			return
		}
		warn, err := m.Save(raw, req.Version)
		switch {
		case errors.Is(err, ErrConflict):
			fail(w, http.StatusConflict, err)
		case err != nil:
			fail(w, http.StatusUnprocessableEntity, err)
		default:
			ok(w, api.CheckResult{OK: true, Warnings: warn})
		}
	})
	mux.HandleFunc("POST /v1/tunnels", func(w http.ResponseWriter, r *http.Request) {
		var req api.TunnelImport
		if !decode(w, r, &req) {
			return
		}
		warn, err := m.ImportTunnel(req)
		if err != nil {
			fail(w, http.StatusUnprocessableEntity, err)
			return
		}
		ok(w, api.CheckResult{OK: true, Warnings: warn})
	})
	mux.HandleFunc("DELETE /v1/tunnels/{name}", func(w http.ResponseWriter, r *http.Request) {
		if err := m.DeleteTunnel(r.PathValue("name")); err != nil {
			fail(w, http.StatusUnprocessableEntity, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

// Listen opens the API socket at path (a Unix socket: Windows 10+ has them;
// access is decided by the file's ACL, set by the installer).
func Listen(path string) (net.Listener, error) {
	_ = os.Remove(path) // left over from a crash
	return net.Listen("unix", path)
}

// Serve answers on l until it is closed.
func (s *Server) Serve(l net.Listener) error {
	srv := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second}
	err := srv.Serve(l)
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// fillRoutes gives processes that were not started in a route the route of
// their app rule, or the default route.
func (s *Server) fillRoutes(ps []api.ProcRoute) {
	def, apps := "block", map[string]string(nil)
	if s.Cfg != nil {
		def, apps = s.Cfg.Summary()
	} else if s.Config != nil {
		def, apps = s.Config()
	}
	for i := range ps {
		if ps[i].Route != "" {
			continue
		}
		ps[i].Route = def
		if r, found := apps[strings.ToLower(ps[i].Name)]; found {
			ps[i].Route = r
		}
	}
}

func ok(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(api.Error{Error: err.Error()})
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(v); err != nil {
		fail(w, http.StatusBadRequest, err)
		return false
	}
	return true
}
