package winsvc

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/Bob-Nixkoenner/the_shunt/internal/api"
	"github.com/Bob-Nixkoenner/the_shunt/internal/check"
)

// ignoreRoutes: hiding warnings, as on Linux (internal/daemon/ignore.go).
// Hiding needs the manage permission; showing again and the list do not.
func (s *Server) ignoreRoutes(mux *http.ServeMux) {
	if s.Ignore == nil {
		s.Ignore, _ = check.OpenIgnore("") // in memory only
	}
	mux.HandleFunc("GET /v1/warnings/ignored", func(w http.ResponseWriter, r *http.Request) {
		l := s.Ignore.List()
		if l == nil {
			l = []check.Ignored{}
		}
		ok(w, l)
	})
	mux.HandleFunc("POST /v1/warnings/ignore", func(w http.ResponseWriter, r *http.Request) {
		var req api.IgnoreRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			fail(w, http.StatusBadRequest, err)
			return
		}
		dur, err := check.ParseFor(req.For)
		if err != nil {
			fail(w, http.StatusBadRequest, err)
			return
		}
		if !s.may(w, r, "hiding a warning") {
			return
		}
		st, err := s.statusAll()
		if err != nil {
			fail(w, http.StatusInternalServerError, err)
			return
		}
		f, found := api.FindHideable(&st, req.Key)
		if !found {
			fail(w, http.StatusNotFound, errors.New("no current warning with this key that can be hidden"))
			return
		}
		it, err := s.Ignore.Hide(f, dur)
		if err != nil {
			fail(w, http.StatusInternalServerError, err)
			return
		}
		log.Printf("api: warning hidden: %s (%s)", it.Key, req.For)
		ok(w, it)
	})
	mux.HandleFunc("DELETE /v1/warnings/ignore", func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Query().Get("key")
		gone, err := s.Ignore.Unhide(key)
		switch {
		case err != nil:
			fail(w, http.StatusInternalServerError, err)
		case !gone:
			fail(w, http.StatusNotFound, errors.New("not hidden"))
		default:
			log.Printf("api: warning shown again: %s", key)
			w.WriteHeader(http.StatusNoContent)
		}
	})
}
