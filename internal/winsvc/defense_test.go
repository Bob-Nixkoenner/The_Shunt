package winsvc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

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
	r := windefense.New(t.TempDir(), nil, nil)
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
