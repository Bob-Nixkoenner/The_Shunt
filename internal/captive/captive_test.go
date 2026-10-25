package captive

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
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

// The probe must look like NetworkManager's own check (libcurl defaults),
// byte for byte: a Go User-Agent or gzip would give The Shunt away.
func TestProbeLooksLikeNetworkManager(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- ""
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		var req strings.Builder
		for {
			l, err := r.ReadString('\n')
			req.WriteString(l)
			if err != nil || l == "\r\n" {
				break
			}
		}
		got <- req.String()
		io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 25\r\nConnection: close\r\n\r\nNetworkManager is online\n")
	}()
	host := ln.Addr().String()
	if state, _ := Probe(context.Background(), "http://"+host+"/check_network_status.txt"); state != Online {
		t.Errorf("state %q", state)
	}
	want := "GET /check_network_status.txt HTTP/1.1\r\nHost: " + host + "\r\nAccept: */*\r\nConnection: close\r\n\r\n"
	if r := <-got; r != want {
		t.Errorf("request\n%q\nwant\n%q", r, want)
	}
}
