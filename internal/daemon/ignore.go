package daemon

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Bob-Nixkoenner/the_shunt/internal/api"
	"github.com/Bob-Nixkoenner/the_shunt/internal/check"
)

// ignoreRoutes: hiding warnings (check/ignore.go). Hiding needs the manage
// permission; showing a warning again and the list do not (more warnings
// are never less safe).
func (d *Daemon) ignoreRoutes(mux *http.ServeMux) {
	list := func() *check.IgnoreList {
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.ignore == nil { // before the first config was applied
			d.ignore, _ = check.OpenIgnore(d.statePath("ignored.json"))
		}
		return d.ignore
	}
	mux.HandleFunc("GET /v1/warnings/ignored", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, nonNil(list().List()))
	})
	mux.HandleFunc("POST /v1/warnings/ignore", func(w http.ResponseWriter, r *http.Request) {
		var req api.IgnoreRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		dur, err := check.ParseFor(req.For)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		if err := d.authorize(r.Context(), peerOf(r.Context())); err != nil {
			writeErr(w, http.StatusForbidden, err)
			return
		}
		st := d.statusAll()
		f, ok := api.FindHideable(&st, req.Key)
		if !ok {
			writeErr(w, http.StatusNotFound, errors.New("no current warning with this key that can be hidden"))
			return
		}
		it, err := list().Hide(f, dur)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		d.Log.Info("warning hidden", "key", it.Key, "for", req.For)
		writeJSON(w, http.StatusOK, it)
	})
	mux.HandleFunc("DELETE /v1/warnings/ignore", func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Query().Get("key")
		ok, err := list().Unhide(key)
		switch {
		case err != nil:
			writeErr(w, http.StatusInternalServerError, err)
		case !ok:
			writeErr(w, http.StatusNotFound, errors.New("not hidden"))
		default:
			d.Log.Info("warning shown again", "key", key)
			w.WriteHeader(http.StatusNoContent)
		}
	})
}

func nonNil(l []check.Ignored) []check.Ignored {
	if l == nil {
		return []check.Ignored{}
	}
	return l
}
