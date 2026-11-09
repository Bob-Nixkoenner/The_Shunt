package ui

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

const testHost = "127.0.0.1:9999"

func testServer() (*Server, http.Handler) {
	s := &Server{host: testHost}
	return s, s.guard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
}

func serve(h http.Handler, method, target string, mod func(*http.Request)) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, nil)
	r.Host = testHost
	if mod != nil {
		mod(r)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// login mints a login URL and redeems it, returning the token and the
// session cookie value.
func login(t *testing.T, s *Server, h http.Handler) (tok, sec string) {
	t.Helper()
	raw, err := s.LoginURL()
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(raw)
	tok = u.Query().Get("t")
	w := serve(h, "GET", "/?t="+tok, nil)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("login: got %d", w.Code)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == cookieName {
			sec = c.Value
		}
	}
	if sec == "" {
		t.Fatal("login set no cookie")
	}
	return tok, sec
}

func withCookie(v string) func(*http.Request) {
	return func(r *http.Request) { r.AddCookie(&http.Cookie{Name: cookieName, Value: v}) }
}

func TestGuard(t *testing.T) {
	s, h := testServer()
	tok, sec := login(t, s, h)
	cookie := withCookie(sec)
	do := func(method, target string, mod func(*http.Request)) int { return serve(h, method, target, mod).Code }
	cases := []struct {
		name string
		code int
		got  int
	}{
		{"no cookie", 401, do("GET", "/api/status", nil)},
		{"wrong token", 403, do("GET", "/?t=nope", nil)},
		{"token is one-time", 403, do("GET", "/?t="+tok, nil)},
		{"login token is no cookie", 401, do("GET", "/api/status", withCookie(tok))},
		{"cookie ok", 204, do("GET", "/api/status", cookie)},
		{"rebinding host", 403, do("GET", "/api/status", func(r *http.Request) { cookie(r); r.Host = "evil.example:9999" })},
		{"foreign origin", 403, do("POST", "/api/panic", func(r *http.Request) {
			cookie(r)
			r.Header.Set("Origin", "http://evil.example")
			r.Header.Set("X-Shunt", "1")
		})},
		{"post without header", 403, do("POST", "/api/panic", cookie)},
		{"post ok", 204, do("POST", "/api/panic", func(r *http.Request) { cookie(r); r.Header.Set("X-Shunt", "1") })},
	}
	for _, c := range cases {
		if c.got != c.code {
			t.Errorf("%s: got %d want %d", c.name, c.got, c.code)
		}
	}
	if tok == sec {
		t.Error("session secret equals the login token")
	}
}

func TestLoginExpires(t *testing.T) {
	s, h := testServer()
	s.LoginTTL = time.Nanosecond
	raw, err := s.LoginURL()
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond)
	u, _ := url.Parse(raw)
	if c := serve(h, "GET", "/?t="+u.Query().Get("t"), nil).Code; c != 403 {
		t.Errorf("expired token: got %d want 403", c)
	}
	if len(s.logins) != 0 {
		t.Errorf("expired token not removed: %d left", len(s.logins))
	}
}

func TestSessionIdle(t *testing.T) {
	s, h := testServer()
	s.SessionIdle = time.Hour
	_, sec := login(t, s, h)
	if c := serve(h, "GET", "/api/status", withCookie(sec)).Code; c != 204 {
		t.Fatalf("fresh session: got %d", c)
	}
	s.sessions[sec] = time.Now().Add(-2 * time.Hour) // idle too long
	if c := serve(h, "GET", "/api/status", withCookie(sec)).Code; c != 401 {
		t.Errorf("idle session: got %d want 401", c)
	}
	if c := serve(h, "GET", "/api/status", withCookie(sec)).Code; c != 401 {
		t.Errorf("idle session must stay dead: got %d", c)
	}
}

func TestSessionsIndependent(t *testing.T) {
	s, h := testServer()
	_, a := login(t, s, h)
	_, b := login(t, s, h)
	if a == b {
		t.Fatal("two logins share one secret")
	}
	for _, sec := range []string{a, b} {
		if c := serve(h, "GET", "/api/status", withCookie(sec)).Code; c != 204 {
			t.Errorf("session %d: got %d", len(sec), c)
		}
	}
}
