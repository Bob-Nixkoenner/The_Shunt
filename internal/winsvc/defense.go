package winsvc

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/Bob-Nixkoenner/the_shunt/internal/api"
	"github.com/Bob-Nixkoenner/the_shunt/internal/defense"
	"github.com/Bob-Nixkoenner/the_shunt/internal/windefense"
)

// defenseRoutes serves /v1/defense* like shuntd does on Linux. Reading is
// open to every caller; changing the config, banning and lifting a block
// need the manage right.
func (s *Server) defenseRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/defense", func(w http.ResponseWriter, r *http.Request) {
		if s.Defense == nil {
			ok(w, defense.Status{Class: defense.ClassUnknown, Level: defense.LevelQuiet, Config: defense.DefaultConfig(),
				Unsupported: "the defense is not running"})
			return
		}
		ok(w, s.Defense.Status())
	})
	mux.HandleFunc("GET /v1/defense/events", func(w http.ResponseWriter, r *http.Request) {
		if s.Defense == nil {
			ok(w, defense.EventsResponse{Events: []defense.Event{}})
			return
		}
		if src := r.URL.Query().Get("src"); src != "" {
			if _, err := netip.ParseAddr(src); err != nil {
				fail(w, http.StatusBadRequest, fmt.Errorf("src: not an IP address"))
				return
			}
			ok(w, s.Defense.M.EventsFor(src))
			return
		}
		since, _ := strconv.ParseUint(r.URL.Query().Get("since"), 10, 64)
		ok(w, s.Defense.M.Events(since))
	})
	mux.HandleFunc("GET /v1/defense/reports", func(w http.ResponseWriter, r *http.Request) {
		if s.Defense == nil {
			ok(w, defense.ReportsResponse{Reports: []defense.NetReport{}})
			return
		}
		ok(w, s.Defense.M.Reports(r.URL.Query().Get("export") == "1"))
	})
	mux.HandleFunc("POST /v1/defense/config", func(w http.ResponseWriter, r *http.Request) {
		if !s.may(w, r, "changing the defense settings") {
			return
		}
		var cfg defense.Config
		if !decode(w, r, &cfg) {
			return
		}
		if s.Defense == nil || s.Cfg == nil {
			fail(w, http.StatusConflict, errors.New("defense is not available"))
			return
		}
		cur := s.Cfg.Current()
		if cur == nil {
			fail(w, http.StatusConflict, errors.New("no config loaded"))
			return
		}
		raw, err := windefense.SaveConfig(cur, cfg)
		if err == nil {
			_, err = s.Cfg.Save(raw, "")
		}
		if err != nil {
			fail(w, http.StatusUnprocessableEntity, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /v1/defense/ban", func(w http.ResponseWriter, r *http.Request) {
		if !s.may(w, r, "blocking an address") {
			return
		}
		var req api.DefenseUnban
		if !decode(w, r, &req) {
			return
		}
		if s.Defense == nil {
			fail(w, http.StatusConflict, errors.New("defense is not available"))
			return
		}
		if err := s.Defense.Ban(strings.TrimSpace(req.Src)); err != nil {
			code := http.StatusBadRequest
			if errors.Is(err, defense.ErrNeverBan) || errors.Is(err, defense.ErrNotBannable) || errors.Is(err, windefense.ErrNoBlocking) {
				code = http.StatusConflict
			}
			fail(w, code, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /v1/defense/unban", func(w http.ResponseWriter, r *http.Request) {
		if !s.may(w, r, "lifting a block") {
			return
		}
		var req api.DefenseUnban
		if !decode(w, r, &req) {
			return
		}
		src := strings.TrimSpace(req.Src)
		if src != "" { // an address, or a range the defense blocked as a whole
			if _, err := netip.ParseAddr(src); err != nil {
				if _, err2 := netip.ParsePrefix(src); err2 != nil {
					fail(w, http.StatusBadRequest, err)
					return
				}
			}
		}
		if s.Defense != nil {
			if src == "" {
				s.Defense.LiftAll("manual") // also what the table may have lost
			} else {
				s.Defense.M.Unban(src)
			}
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
