package ui

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/api"
)

func TestEvidenceProxy(t *testing.T) {
	dir, _ := os.MkdirTemp("", "shd")
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "d.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skip(err)
	}
	var mu sync.Mutex
	var seen []string
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/defense/evidence", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"enabled":true}`)) })
	mux.HandleFunc("/v1/defense/evidence/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
		mu.Unlock()
		if r.Method == "POST" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Write([]byte(`{"ip":"192.0.2.1"}`))
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	s := &Server{host: testHost, Client: api.NewClient(sock)}
	h := s.handler()
	_, sec := login(t, s, h)
	do := func(method, target, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, target, strings.NewReader(body))
		r.Host = testHost
		r.Header.Set("X-Shunt", "1")
		r.AddCookie(&http.Cookie{Name: cookieName, Value: sec})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := do("GET", "/api/defense/evidence", ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"enabled":true`) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if w := do("GET", "/api/defense/evidence/abuse?src=192.0.2.1", ""); w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if w := do("POST", "/api/defense/evidence/case", `{"action":"create","src":"192.0.2.1"}`); w.Code != 200 || !strings.Contains(w.Body.String(), "ok") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	for _, bad := range []string{"/api/defense/evidence/abuse?src=nonsense", "/api/defense/evidence/abuse", "/api/defense/evidence/download?name=../x", "/api/defense/evidence/download?name=chain.json"} {
		if w := do("GET", bad, ""); w.Code != 400 {
			t.Errorf("%s: %d", bad, w.Code)
		}
	}
	if w := do("GET", "/api/defense/evidence/download?name=shunt-case-a1.tar.gz", ""); w.Code != 200 {
		t.Fatalf("%d", w.Code)
	}
	// no session = no access
	r := httptest.NewRequest("GET", "/api/defense/evidence", nil)
	r.Host = testHost
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code == 200 {
		t.Fatal("evidence status without a session")
	}
}

// The desktop window cannot take a browser download: the archive is saved
// into the download folder by the app itself, never overwritten, 0600.
func TestEvidenceSave(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "d.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skip(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/defense/evidence/download", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"name":"` + r.URL.Query().Get("name") + `","size":5,"data":"ZGVtbyE="}`))
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	down := filepath.Join(dir, "Downloads")
	if err := os.Mkdir(down, 0o755); err != nil {
		t.Fatal(err)
	}
	oldD, oldO := downloadsDirFn, openFolderFn
	var opened []string
	downloadsDirFn = func() string { return down }
	openFolderFn = func(p string) { opened = append(opened, p) }
	t.Cleanup(func() { downloadsDirFn, openFolderFn = oldD, oldO })
	s := &Server{host: testHost, Client: api.NewClient(sock)}
	h := s.handler()
	_, sec := login(t, s, h)
	do := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/api/defense/evidence/save", strings.NewReader(body))
		r.Host = testHost
		r.Header.Set("X-Shunt", "1")
		r.AddCookie(&http.Cookie{Name: cookieName, Value: sec})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for i, want := range []string{"shunt-case-a.tar.gz", "shunt-case-a-1.tar.gz"} { // second save must not overwrite
		w := do(`{"name":"shunt-case-a.tar.gz"}`)
		if w.Code != 200 {
			t.Fatalf("save %d: %d %s", i, w.Code, w.Body.String())
		}
		b, err := os.ReadFile(filepath.Join(down, want))
		if err != nil || string(b) != "demo!" {
			t.Fatalf("file %s: %q %v", want, b, err)
		}
		if st, _ := os.Stat(filepath.Join(down, want)); st.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v", st.Mode())
		}
	}
	if len(opened) != 2 {
		t.Fatalf("folder opened %d times", len(opened))
	}
	for _, bad := range []string{`{"name":"../x.tar.gz"}`, `{"name":"x"}`, `{"name":"shunt-case-/../a.tar.gz"}`} {
		if w := do(bad); w.Code != 400 {
			t.Fatalf("%s: %d", bad, w.Code)
		}
	}
}
