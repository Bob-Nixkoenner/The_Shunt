package ui

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
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
	mux.HandleFunc("GET /api/defense/evidence/download", pass("GET", "/v1/defense/evidence/download", func(r *http.Request) (string, bool) {
		n := r.URL.Query().Get("name")
		return "?name=" + url.QueryEscape(n), evExportName.MatchString(n)
	}, false))
	mux.HandleFunc("GET /api/defense/evidence/abuse", pass("GET", "/v1/defense/evidence/abuse", func(r *http.Request) (string, bool) {
		src := r.URL.Query().Get("src")
		_, err := netip.ParseAddr(src)
		return "?src=" + url.QueryEscape(src), err == nil
	}, false))
}
