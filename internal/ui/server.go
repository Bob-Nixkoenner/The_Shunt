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
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/api"
	"github.com/Bob-Nixkoenner/the_shunt/internal/argv"
	"github.com/Bob-Nixkoenner/the_shunt/internal/desktop"
	"github.com/Bob-Nixkoenner/the_shunt/internal/probe"
)

//go:embed static
var static embed.FS

// Server is the UI backend.
type Server struct {
	Socket string // shuntd socket
	Self   string // path of the shunt binary
	Client *api.Client

	token string
	host  string
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

	mux.HandleFunc("GET /api/status", func(w http.ResponseWriter, r *http.Request) {
		var st api.Status
		if err := s.Client.Do("GET", "/v1/status", nil, &st); err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, st)
	})
	mux.HandleFunc("POST /api/panic", func(w http.ResponseWriter, r *http.Request) {
		var req api.PanicRequest
		if !decode(w, r, &req) {
			return
		}
		s.forward(w, "POST", "/v1/panic", req)
	})
	mux.HandleFunc("POST /api/reload", func(w http.ResponseWriter, r *http.Request) {
		s.forward(w, "POST", "/v1/reload", nil)
	})
	mux.HandleFunc("POST /api/run", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Route, Cmd string }
		if !decode(w, r, &req) {
			return
		}
		args, err := argv.Split(req.Cmd)
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
		list, err := desktop.List()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, list)
	})
	mux.HandleFunc("POST /api/apps", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ ID, Route string }
		if !decode(w, r, &req) {
			return
		}
		var err error
		if req.Route == "" {
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
	mux.HandleFunc("DELETE /api/tunnels/{name}", func(w http.ResponseWriter, r *http.Request) {
		s.forward(w, "DELETE", "/v1/tunnels/"+url.PathEscape(r.PathValue("name")), nil)
	})
	mux.HandleFunc("POST /api/launchers", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ App, Name, Args, Route string }
		if !decode(w, r, &req) {
			return
		}
		id, err := desktop.Clone(req.App, req.Name, req.Args, req.Route, s.Self)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, map[string]string{"id": id})
	})
	mux.HandleFunc("GET /api/firefox-profiles", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, desktop.FirefoxProfiles())
	})
	mux.HandleFunc("POST /api/leaktest", func(w http.ResponseWriter, r *http.Request) {
		var st api.Status
		if err := s.Client.Do("GET", "/v1/status", nil, &st); err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		writeJSON(w, probe.LeakTest(ctx, s.Self, s.Socket, st.Routes))
	})
	return s.guard(mux)
}

// launch starts args in route, detached from the UI process.
func (s *Server) launch(route string, args []string) error {
	cmd := exec.Command(s.Self, append([]string{"-s", s.Socket, "run", "--via", route, "--"}, args...)...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
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
