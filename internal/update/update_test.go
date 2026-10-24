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
		// builds from git after a tag: at least that tag
		{"v0.7.1-rc10-4-gf357390-dirty", "v0.7.1-rc10", false},
		{"v0.7.1-rc10-4-gf357390", "v0.7.1-rc9", false},
		{"v0.7.1-rc10-dirty", "v0.7.1-rc10", false},
		{"v0.7.1-rc10-4-gf357390", "v0.7.1-rc11", true},
		{"v0.7.1-rc10-4-gf357390", "v0.7.1", true},
		{"v0.7.0-12-gabc1234", "v0.7.1-rc10", true},
	} {
		if got := newer(tc.cur, tc.latest); got != tc.want {
			t.Errorf("%q vs %q: %v", tc.cur, tc.latest, got)
		}
	}
}

func TestCheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/"+Repo+"/compare/ffff0000aaaa...1234567" {
			w.Write([]byte(`{"status":"behind"}`))
			return
		}
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
		w.Write([]byte(`{"sha":"ffff0000aaaa","status":"behind"}`))
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

// A source build GitHub's newest commit lacks is not outdated: built from
// local commits (unknown to GitHub) or from a branch that is ahead.
func TestSourceBuildAhead(t *testing.T) {
	status := map[string]int{"1111111": http.StatusNotFound, "2222222": 0, "3333333": 0, "4444444": 0}
	body := map[string]string{"2222222": "ahead", "3333333": "identical", "4444444": "diverged"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/"+Repo+"/commits/HEAD" {
			w.Write([]byte(`{"sha":"ffff0000aaaa"}`))
			return
		}
		sha := r.URL.Path[len(r.URL.Path)-7:]
		if status[sha] != 0 {
			w.WriteHeader(status[sha])
			return
		}
		w.Write([]byte(`{"status":"` + body[sha] + `"}`))
	}))
	defer srv.Close()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	for sha, want := range map[string]bool{"1111111": false, "2222222": false, "3333333": false, "4444444": true} {
		c := &Checker{Current: "src-" + sha, API: srv.URL}
		if i := c.Check(context.Background()); i.Available != want || i.Err != "" {
			t.Errorf("%s: %+v", sha, i)
		}
	}
}

func TestCmpVersion(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"v0.7.0-rc8", "v0.7.0-rc7", 1}, {"v0.7.0", "v0.7.0-rc8", 1}, {"v0.6.9", "v0.7.0-rc1", -1},
		{"v0.7.0-rc10", "v0.7.0-rc9", 1}, {"v0.7.0", "v0.7.0", 0},
	} {
		if got, ok := cmpVersion(c.a, c.b); !ok || got != c.want {
			t.Errorf("cmpVersion(%s,%s) = %d,%v want %d", c.a, c.b, got, ok, c.want)
		}
	}
}

func TestLocalBuildNeverAsks(t *testing.T) {
	for _, cur := range []string{"v0.7.1-next", "v0.7.1-wgui3"} {
		if newer(cur, "v0.7.1-rc1") || newer(cur, "v0.8.0") {
			t.Errorf("%s should not be offered an update", cur)
		}
	}
	if !newer("v0.7.1-rc1", "v0.7.1") {
		t.Error("rc1 should see 0.7.1")
	}
}
