package ui

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/api"
	"github.com/Bob-Nixkoenner/the_shunt/internal/defense"
)

// fakeDaemon answers /v1/defense* on a socket and records what it got.
func fakeDaemon(t *testing.T) (sock string, got *[]string) {
	t.Helper()
	dir, _ := os.MkdirTemp("", "shd")
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock = filepath.Join(dir, "d.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skip("no unix sockets:", err)
	}
	var mu sync.Mutex
	rec := []string{}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/defense", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(defense.Status{Enabled: true, Class: defense.ClassPublic, Heat: 42, Level: defense.LevelNoticed})
	})
	mux.HandleFunc("/v1/defense/events", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		rec = append(rec, "events "+r.URL.RawQuery)
		mu.Unlock()
		json.NewEncoder(w).Encode(defense.EventsResponse{LastSeq: 7})
	})
	mux.HandleFunc("/v1/defense/config", func(w http.ResponseWriter, r *http.Request) {
		var c defense.Config
		json.NewDecoder(r.Body).Decode(&c)
		mu.Lock()
		rec = append(rec, "config "+strings.Join(c.Never, ","))
		mu.Unlock()
	})
	mux.HandleFunc("/v1/defense/unban", func(w http.ResponseWriter, r *http.Request) {
		var u api.DefenseUnban
		json.NewDecoder(r.Body).Decode(&u)
		mu.Lock()
		rec = append(rec, "unban "+u.Src)
		mu.Unlock()
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return sock, &rec
}

func TestDefenseRoutes(t *testing.T) {
	sock, got := fakeDaemon(t)
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
	w := do("GET", "/api/defense", "")
	var st defense.Status
	if json.Unmarshal(w.Body.Bytes(), &st); st.Heat != 42 || st.Level != defense.LevelNoticed {
		t.Fatalf("status: %d %s", w.Code, w.Body)
	}
	w = do("GET", "/api/defense/events?since=5", "")
	var ev defense.EventsResponse
	json.Unmarshal(w.Body.Bytes(), &ev)
	if ev.LastSeq != 7 || !strings.Contains(w.Body.String(), `"events":[]`) {
		t.Fatalf("events must be an empty list, not null: %s", w.Body)
	}
	if w = do("POST", "/api/defense/config", `{"enabled":true,"never":["192.0.2.1"]}`); w.Code != 200 {
		t.Fatalf("config: %d %s", w.Code, w.Body)
	}
	if w = do("POST", "/api/defense/unban", `{"src":"198.51.100.9"}`); w.Code != 200 {
		t.Fatalf("unban: %d %s", w.Code, w.Body)
	}
	want := []string{"events since=5", "config 192.0.2.1", "unban 198.51.100.9"}
	if strings.Join(*got, "|") != strings.Join(want, "|") {
		t.Fatalf("daemon got %v, want %v", *got, want)
	}
	// without the header a POST is refused (the guard covers the new routes too)
	r := httptest.NewRequest("POST", "/api/defense/unban", strings.NewReader(`{}`))
	r.Host = testHost
	r.AddCookie(&http.Cookie{Name: cookieName, Value: sec})
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, r)
	if rw.Code != http.StatusForbidden {
		t.Fatalf("POST without X-Shunt: %d", rw.Code)
	}
}
