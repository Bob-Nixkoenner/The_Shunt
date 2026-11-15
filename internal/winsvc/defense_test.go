package winsvc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/Bob-Nixkoenner/the_shunt/internal/netdetect"

	"github.com/Bob-Nixkoenner/the_shunt/internal/defense"
	"github.com/Bob-Nixkoenner/the_shunt/internal/windefense"
)

func TestDefenseRoutes(t *testing.T) {
	get := func(s *Server, path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		return w
	}
	// without a runner: answers, says it is not running
	w := get(&Server{}, "/v1/defense")
	var st defense.Status
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &st) != nil || st.Unsupported == "" {
		t.Fatalf("no runner: %d %s", w.Code, w.Body)
	}
	r := windefense.New(t.TempDir(), nil, nil, nil)
	defer r.Close()
	s := &Server{Defense: r}
	for _, p := range []string{"/v1/defense", "/v1/defense/events?since=0", "/v1/defense/reports", "/v1/defense/events?src=192.0.2.1"} {
		if w := get(s, p); w.Code != 200 {
			t.Errorf("%s: %d %s", p, w.Code, w.Body)
		}
	}
	if w := get(s, "/v1/defense/events?src=nonsense"); w.Code != http.StatusBadRequest {
		t.Errorf("bad src: %d", w.Code)
	}
}

type banFW struct{ bans map[netip.Prefix]bool }

func (f *banFW) SetNever([]netip.Prefix) error { return nil }
func (f *banFW) Add(p netip.Prefix) error      { f.bans[p] = true; return nil }
func (f *banFW) Remove(p netip.Prefix) error   { delete(f.bans, p); return nil }
func (f *banFW) Clear() error                  { f.bans = map[netip.Prefix]bool{}; return nil }

// POST /v1/defense/ban blocks for real now; it needs the manage right,
// refuses the gateway and says so without firewall filters.
func TestDefenseBanRoute(t *testing.T) {
	post := func(s *Server, path, body string, who *Caller) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", path, strings.NewReader(body))
		if who != nil {
			req = req.WithContext(WithCaller(req.Context(), who))
		}
		s.Handler().ServeHTTP(w, req)
		return w
	}
	admin := &Caller{PID: 20, Manage: true}
	r := windefense.New(t.TempDir(), nil, nil, nil)
	defer r.Close()
	c, err := config.Parse("[daemon]\ndefault_route = \"direct\"\n[defense]\nenabled = true\n")
	if err != nil {
		t.Fatal(err)
	}
	r.Apply(c)
	r.Network(netdetect.Info{Iface: "Ethernet", GatewayIP: "192.0.2.1"})
	s := &Server{Defense: r}
	if w := post(s, "/v1/defense/ban", `{"src":"203.0.113.7"}`, admin); w.Code != http.StatusConflict {
		t.Errorf("no firewall: %d %s", w.Code, w.Body)
	}
	fw := &banFW{bans: map[netip.Prefix]bool{}}
	r.UseFirewall(fw)
	if w := post(s, "/v1/defense/ban", `{"src":"203.0.113.7"}`, &Caller{PID: 10}); w.Code != http.StatusForbidden {
		t.Errorf("user: %d", w.Code)
	}
	if w := post(s, "/v1/defense/ban", `{"src":"203.0.113.7"}`, admin); w.Code != http.StatusNoContent || !fw.bans[netip.MustParsePrefix("203.0.113.7/32")] {
		t.Errorf("ban: %d %s %v", w.Code, w.Body, fw.bans)
	}
	if w := post(s, "/v1/defense/ban", `{"src":"192.0.2.1"}`, admin); w.Code != http.StatusConflict {
		t.Errorf("gateway: %d %s", w.Code, w.Body)
	}
	if w := post(s, "/v1/defense/ban", `{"src":"nonsense"}`, admin); w.Code != http.StatusBadRequest {
		t.Errorf("garbage: %d", w.Code)
	}
	if w := post(s, "/v1/defense/unban", `{"src":"nonsense"}`, admin); w.Code != http.StatusBadRequest {
		t.Errorf("unban garbage: %d", w.Code)
	}
	if w := post(s, "/v1/defense/unban", `{"src":""}`, admin); w.Code != http.StatusNoContent || len(fw.bans) != 0 {
		t.Errorf("unban all: %d %v", w.Code, fw.bans)
	}
}
