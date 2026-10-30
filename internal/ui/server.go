// Package ui serves the local web interface (`shunt ui`). It runs as the
// desktop user, never as root, and talks to shuntd through the same API as
// the CLI. Everything is embedded: no CDN, no fonts, no tracking.
//
// Access control: the server binds 127.0.0.1 only and requires a random
// token, handed over once via the URL and then kept in an HttpOnly,
// SameSite=Strict cookie. Host and Origin headers are checked against DNS
// rebinding and cross-site requests.
package ui

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/api"
	"github.com/Bob-Nixkoenner/the_shunt/internal/desktop"
	"github.com/Bob-Nixkoenner/the_shunt/internal/firewall"
	"github.com/Bob-Nixkoenner/the_shunt/internal/probe"
	"github.com/Bob-Nixkoenner/the_shunt/internal/speedtest"
	"github.com/Bob-Nixkoenner/the_shunt/internal/stats"
	"github.com/Bob-Nixkoenner/the_shunt/internal/update"
)

//go:embed static
var static embed.FS

// Server is the UI backend.
type Server struct {
	Socket string // shuntd socket
	Self   string // path of the shunt binary
	Client *api.Client
	// Update, if set, reports whether a newer version is on GitHub.
	Update *update.Checker

	// Apps replaces the Linux menu (.desktop files) with another
	// platform's list of programs; nil: the Linux menu.
	Apps AppSource

	token string
	host  string

	speed speedtest.Job // the speed test the page started (one at a time)
}

// AppSource lists programs and sets the route of one by its ID ("" route =
// back to the default). Windows: programs are rules in shunt.toml.
type AppSource interface {
	List() ([]desktop.Entry, error)
	SetRoute(id, route string) error
}

// Cloner is an AppSource with launchers of its own (Windows: Start menu
// shortcuts); otherwise launchers are .desktop files (desktop.Clone).
type Cloner interface {
	Clone(app, name, args, route string) (string, error)
}

func (s *Server) clone(app, name, args, route string) (string, error) {
	if c, ok := s.Apps.(Cloner); ok {
		return c.Clone(app, name, args, route)
	}
	return desktop.Clone(app, name, args, route, s.Self)
}

// Listen binds 127.0.0.1:port (0 = random) and returns the URL to open.
func (s *Server) Listen(port int) (net.Listener, string, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, "", err
	}
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		ln.Close()
		return nil, "", err
	}
	s.token = hex.EncodeToString(b)
	s.host = ln.Addr().String()
	return ln, fmt.Sprintf("http://%s/?t=%s", s.host, s.token), nil
}

// Serve handles requests until the listener closes.
func (s *Server) Serve(ln net.Listener) error {
	srv := &http.Server{Handler: s.handler(), ReadHeaderTimeout: 10 * time.Second}
	return srv.Serve(ln)
}

func (s *Server) handler() http.Handler {
	mux := http.NewServeMux()
	sub, _ := fs.Sub(static, "static")
	files := http.FileServer(http.FS(sub))
	mux.Handle("GET /", files)
	mux.HandleFunc("GET /i18n-data.js", serveI18N)

	mux.HandleFunc("GET /api/status", func(w http.ResponseWriter, r *http.Request) {
		var st api.Status
		if err := s.Client.Do("GET", "/v1/status", nil, &st); err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, st)
	})
	mux.HandleFunc("GET /api/history", func(w http.ResponseWriter, r *http.Request) {
		var h stats.History
		if err := s.Client.Do("GET", "/v1/history?range="+url.QueryEscape(r.URL.Query().Get("range")), nil, &h); err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, h)
	})
	mux.HandleFunc("POST /api/panic", func(w http.ResponseWriter, r *http.Request) {
		var req api.PanicRequest
		if !decode(w, r, &req) {
			return
		}
		s.forward(w, "POST", "/v1/panic", req)
	})
	mux.HandleFunc("POST /api/pass", func(w http.ResponseWriter, r *http.Request) {
		var req api.PassRequest
		if !decode(w, r, &req) {
			return
		}
		s.forward(w, "POST", "/v1/pass", req)
	})
	mux.HandleFunc("POST /api/torall", func(w http.ResponseWriter, r *http.Request) {
		var req api.TorAllRequest
		if !decode(w, r, &req) {
			return
		}
		s.forward(w, "POST", "/v1/torall", req)
	})
	mux.HandleFunc("POST /api/reload", func(w http.ResponseWriter, r *http.Request) {
		s.forward(w, "POST", "/v1/reload", nil)
	})
	mux.HandleFunc("POST /api/dnsfilter/refresh", func(w http.ResponseWriter, r *http.Request) {
		s.forward(w, "POST", "/v1/dnsfilter/refresh", nil)
	})
	mux.HandleFunc("POST /api/restart", func(w http.ResponseWriter, r *http.Request) {
		s.forward(w, "POST", "/v1/restart", nil)
	})
	mux.HandleFunc("POST /api/run", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Route, Cmd string }
		if !decode(w, r, &req) {
			return
		}
		args, err := splitCmd(req.Cmd)
		if err != nil || len(args) == 0 {
			writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid command"))
			return
		}
		if err := s.launch(req.Route, args); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("GET /api/apps", func(w http.ResponseWriter, r *http.Request) {
		var list []desktop.Entry
		var err error
		if s.Apps != nil {
			list, err = s.Apps.List()
		} else {
			list, err = desktop.List()
		}
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		for i := range list {
			if list[i].Clone == "" && list[i].Chromium == "" {
				list[i].Chromium = desktop.ChromiumBrowserOf(list[i].ID)
			}
		}
		writeJSON(w, list)
	})
	mux.HandleFunc("POST /api/captive", func(w http.ResponseWriter, r *http.Request) {
		// a throwaway browser past the tunnels, for the Wi-Fi login page
		cmd := exec.Command(s.Self, "-s", s.Socket, "captive")
		if err := cmd.Start(); err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		go func() { _ = cmd.Wait() }()
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("GET /api/update", func(w http.ResponseWriter, r *http.Request) {
		if s.Update == nil {
			writeJSON(w, update.Info{Disabled: true})
			return
		}
		writeJSON(w, s.Update.Get())
	})
	mux.HandleFunc("POST /api/update", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Enabled     *bool
			Releases    *bool
			Prereleases *bool
		}
		if !decode(w, r, &req) {
			return
		}
		var err error
		if req.Releases != nil || req.Prereleases != nil {
			rel, pre := update.Releases(), update.Prereleases()
			if !update.Enabled() { // everything was off: change from there
				rel, pre = false, false
			}
			if req.Releases != nil {
				rel = *req.Releases
			}
			if req.Prereleases != nil {
				pre = *req.Prereleases
			}
			err = update.SetChannels(rel, pre)
		} else if req.Enabled != nil {
			err = update.SetEnabled(*req.Enabled)
		}
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		if update.Enabled() && s.Update != nil {
			s.Update.Check(r.Context())
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /api/update/apply", func(w http.ResponseWriter, r *http.Request) {
		if s.Update == nil {
			writeErr(w, http.StatusBadRequest, update.ErrNotSupported)
			return
		}
		// the download can take a while; the browser's request must not cancel it half way
		if err := s.Update.Apply(context.WithoutCancel(r.Context())); err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("GET /api/update/progress", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, update.GetProgress())
	})
	mux.HandleFunc("GET /api/pending", func(w http.ResponseWriter, r *http.Request) {
		var ps []firewall.Pending
		if err := s.Client.Do("GET", "/v1/pending", nil, &ps); err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, ps)
	})
	mux.HandleFunc("POST /api/pending/{id}", func(w http.ResponseWriter, r *http.Request) {
		var req api.FirewallDecision
		if !decode(w, r, &req) {
			return
		}
		s.forward(w, "POST", "/v1/pending/"+url.PathEscape(r.PathValue("id")), req)
	})
	mux.HandleFunc("POST /api/inbound/network", func(w http.ResponseWriter, r *http.Request) {
		var req api.InboundDecision
		if !decode(w, r, &req) {
			return
		}
		s.forward(w, "POST", "/v1/inbound/network", req)
	})
	mux.HandleFunc("GET /api/firewall/apps", func(w http.ResponseWriter, r *http.Request) {
		var rs []firewall.Remembered
		if err := s.Client.Do("GET", "/v1/firewall/apps", nil, &rs); err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, rs)
	})
	mux.HandleFunc("DELETE /api/firewall/apps", func(w http.ResponseWriter, r *http.Request) {
		s.forward(w, "DELETE", "/v1/firewall/apps?key="+url.QueryEscape(r.URL.Query().Get("key")), nil)
	})
	mux.HandleFunc("GET /api/listening", func(w http.ResponseWriter, r *http.Request) {
		var l api.Listening
		if err := s.Client.Do("GET", "/v1/listening", nil, &l); err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, l)
	})
	mux.HandleFunc("GET /api/procs", func(w http.ResponseWriter, r *http.Request) {
		var ps []api.ProcRoute
		if err := s.Client.Do("GET", "/v1/procs?name="+url.QueryEscape(r.URL.Query().Get("name")), nil, &ps); err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, ps)
	})
	mux.HandleFunc("POST /api/apps", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ ID, Route string }
		if !decode(w, r, &req) {
			return
		}
		var err error
		if s.Apps != nil {
			err = s.Apps.SetRoute(req.ID, req.Route)
		} else if req.Route == "" {
			err = desktop.Unset(req.ID)
		} else {
			err = desktop.SetRoute(req.ID, req.Route, s.Self)
		}
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("GET /api/config", func(w http.ResponseWriter, r *http.Request) {
		var v api.ConfigView
		if err := s.Client.Do("GET", "/v1/config", nil, &v); err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, v)
	})
	for _, rt := range []struct{ method, ui, daemon string }{
		{"POST", "/api/config/check", "/v1/config/check"},
		{"PUT", "/api/config", "/v1/config"},
		{"POST", "/api/tunnels", "/v1/tunnels"},
	} {
		mux.HandleFunc(rt.method+" "+rt.ui, func(w http.ResponseWriter, r *http.Request) {
			var body json.RawMessage
			if !decode(w, r, &body) {
				return
			}
			var res api.CheckResult
			if err := s.Client.Do(rt.method, rt.daemon, body, &res); err != nil {
				writeErr(w, http.StatusUnprocessableEntity, err)
				return
			}
			writeJSON(w, res)
		})
	}
	mux.HandleFunc("POST /api/tunnels/{name}/newnym", func(w http.ResponseWriter, r *http.Request) {
		s.forward(w, "POST", "/v1/tunnels/"+url.PathEscape(r.PathValue("name"))+"/newnym", nil)
	})
	mux.HandleFunc("DELETE /api/tunnels/{name}", func(w http.ResponseWriter, r *http.Request) {
		s.forward(w, "DELETE", "/v1/tunnels/"+url.PathEscape(r.PathValue("name")), nil)
	})
	mux.HandleFunc("POST /api/tunnels/{name}/rename", func(w http.ResponseWriter, r *http.Request) {
		var body json.RawMessage
		if !decode(w, r, &body) {
			return
		}
		s.forward(w, "POST", "/v1/tunnels/"+url.PathEscape(r.PathValue("name"))+"/rename", body)
	})
	mux.HandleFunc("POST /api/launchers", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ App, Name, Args, Route string }
		if !decode(w, r, &req) {
			return
		}
		if home, err := os.UserHomeDir(); err == nil {
			req.Args = strings.ReplaceAll(req.Args, "{home}", home)
		}
		id, err := s.clone(req.App, req.Name, req.Args, req.Route)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, map[string]string{"id": id})
	})
	mux.HandleFunc("GET /api/chromium-profiles", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, desktop.ChromiumProfiles())
	})
	// a launcher for an existing Chromium-family profile: the profile gets a
	// data directory of its own (see desktop.ChromiumInstance), so it can have its own route
	mux.HandleFunc("POST /api/profile-launchers", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			App, Name, Route string
			Profile          desktop.ChromiumProfile
		}
		if !decode(w, r, &req) {
			return
		}
		home, err := os.UserHomeDir()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		dir, err := desktop.ChromiumInstance(home, req.Profile, req.Name)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		id, err := s.clone(req.App, req.Name, `--user-data-dir="`+dir+`"`, req.Route)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, map[string]string{"id": id})
	})
	mux.HandleFunc("GET /api/firefox-profiles", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, desktop.FirefoxProfiles())
	})
	mux.HandleFunc("GET /api/ui-state", func(w http.ResponseWriter, r *http.Request) {
		uiStateMu.Lock()
		st := loadUIState()
		uiStateMu.Unlock()
		writeJSON(w, st)
	})
	mux.HandleFunc("PUT /api/ui-state", func(w http.ResponseWriter, r *http.Request) {
		var changes map[string]*string
		if !decode(w, r, &changes) {
			return
		}
		st, err := mergeUIState(changes)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, st)
	})
	mux.HandleFunc("POST /api/open-url", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ URL string }
		if !decode(w, r, &req) {
			return
		}
		if err := openURL(req.URL); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, map[string]string{"ok": "1"})
	})
	s.speed.OnDone = func(rep *speedtest.Report) {
		var st api.Status
		_ = s.Client.Do("GET", "/v1/status", nil, &st)
		_ = speedtest.AddHistory(speedtest.HistoryPath(), rep, st.Network)
	}
	mux.HandleFunc("GET /api/speedtest/history", func(w http.ResponseWriter, r *http.Request) {
		h := speedtest.LoadHistory(speedtest.HistoryPath())
		if h == nil {
			h = []speedtest.HistEntry{}
		}
		writeJSON(w, h)
	})
	mux.HandleFunc("GET /api/speedtest", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, s.speed.State())
	})
	mux.HandleFunc("POST /api/speedtest", func(w http.ResponseWriter, r *http.Request) {
		var o speedtest.Options
		if !decode(w, r, &o) {
			return
		}
		o.MaxPause = 0 // the default pause; not for callers to shorten
		if o.Provider == speedtest.NDT7 {
			var st api.Status
			if err := s.Client.Do("GET", "/v1/status", nil, &st); err != nil {
				writeErr(w, http.StatusBadGateway, err)
				return
			}
			tor := map[string]bool{}
			for _, t := range st.Tunnels {
				if t.Bootstrap != nil {
					tor["tunnel:"+t.Name] = true
				}
			}
			var dropped []string
			if o.Routes, dropped = speedtest.WithoutTor(o.Routes, tor); len(dropped) > 0 {
				writeErr(w, http.StatusBadRequest, errors.New("M-Lab NDT7 does not work through Tor – choose Cloudflare for Tor routes"))
				return
			}
		}
		started, err := s.speed.Start(s.Client.SpeedStep, o)
		switch {
		case err != nil:
			writeErr(w, http.StatusBadRequest, err)
		case !started:
			writeErr(w, http.StatusConflict, errors.New("a speed test is running already"))
		default:
			writeJSON(w, s.speed.State())
		}
	})
	mux.HandleFunc("DELETE /api/speedtest", func(w http.ResponseWriter, r *http.Request) {
		s.speed.Cancel()
		writeJSON(w, s.speed.State())
	})
	mux.HandleFunc("POST /api/leaktest", func(w http.ResponseWriter, r *http.Request) {
		var st api.Status
		if err := s.Client.Do("GET", "/v1/status", nil, &st); err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		writeJSON(w, probe.LeakTest(ctx, s.Client.Probe, st.Routes))
	})
	return s.guard(mux)
}

// launch starts args in route, detached from the UI process.
func (s *Server) launch(route string, args []string) error {
	cmd := exec.Command(s.Self, append([]string{"-s", s.Socket, "run", "--via", route, "--"}, args...)...)
	detach(cmd)
	devnull, _ := os.Open(os.DevNull)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = devnull, devnull, devnull
	if err := cmd.Start(); err != nil {
		return err
	}
	// shunt run exits early only on errors (otherwise it exec()s the app)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("could not start %s via %s (is the route valid?)", args[0], route)
		}
	case <-time.After(700 * time.Millisecond):
	}
	return nil
}

func (s *Server) forward(w http.ResponseWriter, method, path string, body any) {
	if err := s.Client.Do(method, path, body, nil); err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

const cookieName = "shunt_ui"

// guard enforces host, origin and token checks on every request.
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != s.host {
			http.Error(w, "bad host", http.StatusForbidden) // DNS rebinding
			return
		}
		if o := r.Header.Get("Origin"); o != "" && o != "http://"+s.host {
			http.Error(w, "bad origin", http.StatusForbidden)
			return
		}
		if t := r.URL.Query().Get("t"); t != "" && r.URL.Path == "/" {
			if subtle.ConstantTimeCompare([]byte(t), []byte(s.token)) != 1 {
				http.Error(w, "bad token", http.StatusForbidden)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: cookieName, Value: s.token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
			http.Redirect(w, r, "/", http.StatusSeeOther) // drop the token from the address bar
			return
		}
		c, err := r.Cookie(cookieName)
		if err != nil || subtle.ConstantTimeCompare([]byte(c.Value), []byte(s.token)) != 1 {
			http.Error(w, "open the address printed by `shunt ui`", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet && r.Header.Get("X-Shunt") != "1" {
			http.Error(w, "missing X-Shunt header", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(api.Error{Error: err.Error()})
}

// OpenBrowser tries xdg-open; failures are only logged.
func OpenBrowser(url string) {
	if err := exec.Command("xdg-open", url).Start(); err != nil {
		log.Printf("could not open a browser: %v", err)
	}
}
