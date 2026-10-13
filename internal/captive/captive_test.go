package captive

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProbe(t *testing.T) {
	mode := "online"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch mode {
		case "online":
			w.Write([]byte("NetworkManager is online\n"))
		case "redirect":
			http.Redirect(w, r, "http://login.hotel.example/?x=1", http.StatusFound)
		case "page":
			w.Write([]byte("<html>Welcome, please log in</html>"))
		}
	}))
	defer srv.Close()
	for _, tc := range []struct{ mode, state, login string }{
		{"online", Online, ""},
		{"redirect", Portal, "http://login.hotel.example/?x=1"},
		{"page", Portal, srv.URL},
	} {
		mode = tc.mode
		s, l := Probe(context.Background(), srv.URL)
		if s != tc.state || l != tc.login {
			t.Errorf("%s: %s %q", tc.mode, s, l)
		}
	}
	srv.Close()
	if s, _ := Probe(context.Background(), srv.URL); s != Offline {
		t.Errorf("closed server: %s", s)
	}
}
