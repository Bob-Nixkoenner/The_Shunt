package ui

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestSplitCommand(t *testing.T) {
	for in, want := range map[string][]string{
		`firefox -no-remote -P`:        {"firefox", "-no-remote", "-P"},
		`app "with space" 'single $x'`: {"app", "with space", "single $x"},
		`a\ b "c\"d"`:                  {"a b", `c"d`},
		`x ""`:                         {"x", ""},
	} {
		got, err := SplitCommand(in)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("%s: got %q %v", in, got, err)
		}
	}
	if _, err := SplitCommand(`unterminated "quote`); err == nil {
		t.Error("expected error")
	}
}

func TestGuard(t *testing.T) {
	s := &Server{token: "secret", host: "127.0.0.1:9999"}
	h := s.guard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	do := func(method, target string, mod func(*http.Request)) int {
		r := httptest.NewRequest(method, target, nil)
		r.Host = "127.0.0.1:9999"
		if mod != nil {
			mod(r)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	cookie := func(r *http.Request) { r.AddCookie(&http.Cookie{Name: cookieName, Value: "secret"}) }
	cases := []struct {
		name string
		code int
		got  int
	}{
		{"no cookie", 401, do("GET", "/api/status", nil)},
		{"wrong token", 403, do("GET", "/?t=nope", nil)},
		{"token login redirects", 303, do("GET", "/?t=secret", nil)},
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
}
