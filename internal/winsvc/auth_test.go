package winsvc

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/api"
	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
)

// call sends one request as caller (nil = unknown) and returns the status.
func call(t *testing.T, s *Server, who *Caller, method, path string, body any) int {
	t.Helper()
	var b []byte
	if body != nil {
		b, _ = json.Marshal(body)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(b))
	if who != nil {
		req = req.WithContext(WithCaller(req.Context(), who))
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec.Code
}

func authServer(t *testing.T) (*Server, map[int]string) {
	m, _ := newMgr(t)
	if _, err := m.ImportTunnel(api.TunnelImport{Name: "home", Conf: wgConf()}); err != nil {
		t.Fatal(err)
	}
	pinned := map[int]string{}
	routes := map[int]string{30: "tunnel:home"} // pid 30 already runs in a route
	procs := map[int]ProcInfo{
		11: {Parent: 10, Created: time.Unix(200, 0)}, // child of caller 10
		12: {Parent: 99, Created: time.Unix(200, 0)}, // someone else's
		13: {Parent: 10, Created: time.Unix(50, 0)},  // older than the caller: recycled PID
		31: {Parent: 30, Created: time.Unix(200, 0)}, // child of a caller in a tunnel
	}
	s := &Server{Core: &fakeCore{}, Cfg: m,
		Reload:  func() error { return nil },
		Restart: func() {},
		Pin:     func(pid int, route string) error { pinned[pid] = route; return nil },
		ProcInfo: func(pid int) (ProcInfo, error) {
			p, ok := procs[pid]
			if !ok {
				return ProcInfo{}, ErrForbidden
			}
			return p, nil
		},
		RouteOf: func(pid int) string { return routes[pid] }}
	return s, pinned
}

// Every local user reads and may panic; only managers change anything.
func TestAuthorizeEndpoints(t *testing.T) {
	s, _ := authServer(t)
	user := &Caller{PID: 10, Created: time.Unix(100, 0), User: "u"}
	admin := &Caller{PID: 20, Manage: true}
	cfg := api.ConfigSave{Raw: "[daemon]\ndefault_route = \"block\"\n"}
	cases := []struct {
		method, path string
		body         any
		user         int // also for an unknown caller
		admin        int
	}{
		{"GET", "/v1/status", nil, 200, 200},
		{"GET", "/v1/history", nil, 200, 200},
		{"GET", "/v1/config", nil, 200, 200},
		{"GET", "/v1/procs", nil, 200, 200},
		{"POST", "/v1/config/check", cfg, 200, 200},
		{"POST", "/v1/probe", api.ProbeRequest{Route: "direct"}, 200, 200},
		{"POST", "/v1/panic", api.PanicRequest{On: true}, 200, 200},
		{"POST", "/v1/pass", api.PassRequest{Minutes: 0}, 200, 200},
		{"POST", "/v1/panic", api.PanicRequest{On: false}, 403, 200},
		{"POST", "/v1/pass", api.PassRequest{Minutes: 60}, 403, 200},
		{"POST", "/v1/reload", nil, 403, 200},
		{"POST", "/v1/restart", nil, 403, 200},
		{"PUT", "/v1/config", cfg, 403, 200},
		{"POST", "/v1/tunnels", api.TunnelImport{Name: "work", Conf: wgConf()}, 403, 200},
		{"DELETE", "/v1/tunnels/work", nil, 403, 204},
	}
	for _, c := range cases {
		for _, who := range []*Caller{nil, user} {
			if got := call(t, s, who, c.method, c.path, c.body); got != c.user {
				t.Errorf("%s %s as %v: %d, want %d", c.method, c.path, who, got, c.user)
			}
		}
		if got := call(t, s, admin, c.method, c.path, c.body); got != c.admin {
			t.Errorf("%s %s as admin: %d, want %d", c.method, c.path, got, c.admin)
		}
	}
}

// A user may start their own app in a route, but not move other processes
// and not leave the route they run in.
func TestAuthorizeRun(t *testing.T) {
	s, pinned := authServer(t)
	user := &Caller{PID: 10, Created: time.Unix(100, 0)}
	inTunnel := &Caller{PID: 30, Created: time.Unix(100, 0)}
	admin := &Caller{PID: 20, Manage: true}
	cases := []struct {
		who   *Caller
		pid   int
		route string
		want  int
	}{
		{user, 11, "direct", 200},
		{user, 11, "tunnel:home", 200},
		{user, 12, "direct", 403},          // not the caller's child
		{user, 13, "direct", 403},          // PID older than the caller
		{user, 30, "direct", 403},          // someone else's, already in a route
		{nil, 11, "direct", 403},           // unknown caller
		{inTunnel, 31, "direct", 403},      // escape from the caller's tunnel
		{inTunnel, 31, "block", 200},       // tighter is fine
		{inTunnel, 31, "tunnel:home", 200}, // same route
		{admin, 12, "direct", 200},
		{admin, 30, "direct", 200},
	}
	for _, c := range cases {
		delete(pinned, c.pid)
		got := call(t, s, c.who, "POST", "/v1/run", api.RunRequest{PID: c.pid, Route: c.route})
		if got != c.want {
			t.Errorf("%+v pid %d -> %s: %d, want %d", c.who, c.pid, c.route, got, c.want)
		}
		if _, did := pinned[c.pid]; did != (c.want == 200) {
			t.Errorf("pid %d pinned=%v with status %d", c.pid, did, got)
		}
	}
	// without ProcInfo only managers may run
	s.ProcInfo = nil
	if got := call(t, s, user, "POST", "/v1/run", api.RunRequest{PID: 11, Route: "direct"}); got != 403 {
		t.Errorf("run without ProcInfo: %d", got)
	}
}

// Who may manage is not changed through the API.
func TestManageGroupProtected(t *testing.T) {
	m, _ := newMgr(t)
	if g := m.ManageGroup(); g != DefaultManageGroup {
		t.Fatalf("default group %q", g)
	}
	for _, raw := range []string{
		"[daemon]\ndefault_route = \"direct\"\nsocket_group = \"Users\"\n",
		"[daemon]\ndefault_route = \"direct\"\napi_auth = \"group\"\n",
	} {
		if _, err := m.Save([]byte(raw), ""); err == nil || !strings.Contains(err.Error(), "socket_group") {
			t.Errorf("save %q: %v", raw, err)
		}
		if _, err := m.Check([]byte(raw)); err == nil {
			t.Errorf("check %q passed", raw)
		}
	}
	raw, err := m.RawOf(api.ConfigSave{Config: &config.Config{Daemon: config.Daemon{DefaultRoute: "direct", SocketGroup: "Users"}}})
	if err != nil || strings.Contains(string(raw), "Users") {
		t.Errorf("structured save keeps socket_group: %v %s", err, raw)
	}
	if g := m.ManageGroup(); g != DefaultManageGroup {
		t.Fatalf("group changed to %q", g)
	}
}
