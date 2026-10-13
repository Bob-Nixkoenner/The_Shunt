package update

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewer(t *testing.T) {
	for _, tc := range []struct {
		cur, latest string
		want        bool
	}{
		{"src-1a2b3c4", "1a2b3c4d5e6f", false},
		{"src-1a2b3c4", "9f9f9f9f9f9f", true},
		{"v0.6.0", "v0.6.0", false},
		{"v0.6.0", "v0.7.0", true},
		{"dev", "v1.0.0", false},
		{"v0.6.0", "", false},
	} {
		if got := newer(tc.cur, tc.latest); got != tc.want {
			t.Errorf("%q vs %q: %v", tc.cur, tc.latest, got)
		}
	}
}

func TestCheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/"+Repo+"/commits/HEAD" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(`{"sha":"ffff0000aaaa","commit":{}}`))
	}))
	defer srv.Close()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	calls := 0
	c := &Checker{Current: "src-1234567", API: srv.URL, OnAvailable: func(Info) { calls++ }}
	i := c.Check(context.Background())
	if !i.Available || i.Command == "" || i.Latest != "ffff0000aaaa" {
		t.Fatalf("%+v", i)
	}
	c.Check(context.Background())
	if calls != 1 {
		t.Errorf("OnAvailable called %d times", calls)
	}
	if err := SetEnabled(false); err != nil || Enabled() {
		t.Fatal("disable failed")
	}
	if !c.Get().Disabled {
		t.Error("Get does not report disabled")
	}
	SetEnabled(true)
	if !Enabled() {
		t.Error("enable failed")
	}
}

func TestInstalledChanges(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"sha":"ffff0000aaaa"}`))
	}))
	defer srv.Close()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	inst := "src-1234567"
	c := &Checker{Current: "src-1234567", API: srv.URL, Installed: func() string { return inst }}
	if !c.Check(context.Background()).Available {
		t.Fatal("no update found")
	}
	inst = "src-ffff000" // updated, app not restarted
	if i := c.Get(); i.Available || i.Current != "src-ffff000" {
		t.Errorf("stale result after update: %+v", i)
	}
}
