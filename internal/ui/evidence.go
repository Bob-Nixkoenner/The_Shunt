package ui

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

var evExportName = regexp.MustCompile(`^shunt-case-[A-Za-z0-9._-]+\.tar\.gz$`)

// evidenceRoutes forwards the evidence calls (Defense tab, section
// "Evidence") to the daemon. Nothing is cached or kept here.
func (s *Server) evidenceRoutes(mux *http.ServeMux) {
	pass := func(method, path string, query func(r *http.Request) (string, bool), body bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			p := path
			if query != nil {
				q, ok := query(r)
				if !ok {
					writeErr(w, http.StatusBadRequest, fmt.Errorf("bad request"))
					return
				}
				p += q
			}
			var in any
			if body {
				var raw json.RawMessage
				if !decode(w, r, &raw) {
					return
				}
				in = raw
			}
			var out json.RawMessage
			if err := s.Client.Do(method, p, in, &out); err != nil && !errors.Is(err, io.EOF) { // 204: no body
				writeErr(w, http.StatusBadGateway, err)
				return
			}
			if len(out) == 0 {
				out = json.RawMessage(`{"ok":true}`)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(out)
		}
	}
	mux.HandleFunc("GET /api/defense/evidence", pass("GET", "/v1/defense/evidence", nil, false))
	mux.HandleFunc("POST /api/defense/evidence/case", pass("POST", "/v1/defense/evidence/case", nil, true))
	mux.HandleFunc("POST /api/defense/evidence/purge", pass("POST", "/v1/defense/evidence/purge", nil, true))
	mux.HandleFunc("POST /api/defense/evidence/export", pass("POST", "/v1/defense/evidence/export", nil, true))
	mux.HandleFunc("GET /api/defense/evidence/networks", pass("GET", "/v1/defense/evidence/networks", nil, false))
	mux.HandleFunc("GET /api/defense/evidence/download", pass("GET", "/v1/defense/evidence/download", func(r *http.Request) (string, bool) {
		n := r.URL.Query().Get("name")
		return "?name=" + url.QueryEscape(n), evExportName.MatchString(n)
	}, false))
	mux.HandleFunc("GET /api/defense/evidence/abuse", pass("GET", "/v1/defense/evidence/abuse", func(r *http.Request) (string, bool) {
		src := r.URL.Query().Get("src")
		_, err := netip.ParseAddr(src)
		return "?src=" + url.QueryEscape(src), err == nil
	}, false))
	mux.HandleFunc("POST /api/defense/evidence/save", s.evidenceSave)
	mux.HandleFunc("POST /api/defense/reports/save", s.reportsSave)
}

// downloadsDir is where a saved archive goes: the user's download folder
// (XDG on Linux), else ~/Downloads, else the home directory.
// downloadsDirFn and openFolderFn are variables so a test can replace them.
var (
	downloadsDirFn = downloadsDir
	openFolderFn   = openFolder
)

func downloadsDir() string {
	if runtime.GOOS == "linux" {
		if out, err := exec.Command("xdg-user-dir", "DOWNLOAD").Output(); err == nil {
			if d := strings.TrimSpace(string(out)); d != "" && d != os.Getenv("HOME") {
				return d
			}
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return os.TempDir()
	}
	if d := filepath.Join(home, "Downloads"); isDir(d) {
		return d
	}
	return home
}

func isDir(p string) bool { st, err := os.Stat(p); return err == nil && st.IsDir() }

// evidenceSave fetches a finished archive from the daemon (the daemon's
// folder belongs to root) and writes it into the user's download folder.
// The desktop window cannot take a browser download, so the page does not
// rely on one. The folder opens in the file manager, best effort.
func (s *Server) evidenceSave(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &in) {
		return
	}
	if !evExportName.MatchString(in.Name) {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("bad request"))
		return
	}
	var d struct {
		Name string `json:"name"`
		Data string `json:"data"`
	}
	if err := s.Client.Do("GET", "/v1/defense/evidence/download?name="+url.QueryEscape(in.Name), nil, &d); err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	raw, err := base64.StdEncoding.DecodeString(d.Data)
	if err != nil || len(raw) == 0 {
		writeErr(w, http.StatusBadGateway, fmt.Errorf("the archive could not be read"))
		return
	}
	path, err := saveAs(in.Name, ".tar.gz", raw)
	if errors.Is(err, errCancelled) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"cancelled": true})
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	dir := filepath.Dir(path)
	openFolderFn(path)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"path": path, "dir": dir, "size": len(raw)})
}

// saveAs lets the user pick the place with the system's save dialog (the
// suggestion is the download folder, never overwriting an earlier export).
// Without a dialog it saves to that suggestion. errCancelled: nothing written.
func saveAs(name, ext string, raw []byte) (string, error) {
	dir := downloadsDirFn()
	path := filepath.Join(dir, name)
	for i := 1; ; i++ { // never overwrite an earlier export
		if _, err := os.Lstat(path); err != nil {
			break
		}
		path = filepath.Join(dir, strings.TrimSuffix(name, ext)+fmt.Sprintf("-%d%s", i, ext))
	}
	switch chosen, err := saveDialogFn(path); {
	case errors.Is(err, errCancelled):
		return "", err
	case err == nil:
		path = chosen // the dialog asked about overwriting
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// reportsSave writes the network reports through the same dialog.
func (s *Server) reportsSave(w http.ResponseWriter, r *http.Request) {
	rep, err := s.Client.DefenseReports(true)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	raw, _ := json.MarshalIndent(rep, "", "  ")
	path, err := saveAs("shunt-network-report.json", ".json", raw)
	w.Header().Set("Content-Type", "application/json")
	switch {
	case errors.Is(err, errCancelled):
		_ = json.NewEncoder(w).Encode(map[string]any{"cancelled": true})
	case err != nil:
		writeErr(w, http.StatusInternalServerError, err)
	default:
		openFolderFn(path)
		_ = json.NewEncoder(w).Encode(map[string]any{"path": path})
	}
}

// openFolder shows the file in the file manager; failures are not an error.
func openFolder(path string) {
	var c *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		c = exec.Command("explorer", "/select,"+path)
	case "darwin":
		c = exec.Command("open", "-R", path)
	default:
		c = exec.Command("xdg-open", filepath.Dir(path))
	}
	if c.Start() == nil {
		go func() { _ = c.Wait() }()
	}
}
