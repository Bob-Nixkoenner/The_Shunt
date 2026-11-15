package winsvc

import (
	"net/http"
	"path/filepath"
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/api"
	"github.com/Bob-Nixkoenner/the_shunt/internal/check"
)

// The routes exist on Windows too: hiding needs a manager and a current
// warning that may be hidden; listing and showing again are open.
func TestIgnoreRoutesWindows(t *testing.T) {
	s, _ := authServer(t)
	s.Ignore, _ = check.OpenIgnore(filepath.Join(t.TempDir(), "ignored.json"))
	admin := &Caller{PID: 10, Manage: true}
	user := &Caller{PID: 20}
	if c := call(t, s, user, "GET", "/v1/warnings/ignored", nil); c != http.StatusOK {
		t.Fatalf("list: %d", c)
	}
	if c := call(t, s, user, "POST", "/v1/warnings/ignore", api.IgnoreRequest{Key: "quiet.off", For: "day"}); c != http.StatusForbidden {
		t.Fatalf("user hides: %d", c)
	}
	if c := call(t, s, admin, "POST", "/v1/warnings/ignore", api.IgnoreRequest{Key: "quiet.off", For: "day"}); c != http.StatusNotFound {
		t.Fatalf("hide a warning that is not there: %d", c)
	}
	// an entry from the file (hidden earlier) is listed and can be taken back
	if _, err := s.Ignore.Hide(check.Finding{ID: "quiet.off", Level: check.Info}, 0); err != nil {
		t.Fatal(err)
	}
	st, err := s.Status()
	if err != nil || len(st.Ignored) != 1 || st.Ignored[0].Hiding || st.Hidden != 0 {
		t.Fatalf("status: %v %+v", err, st.Ignored)
	}
	if c := call(t, s, user, "DELETE", "/v1/warnings/ignore?key=quiet.off", nil); c != http.StatusNoContent {
		t.Fatalf("show again: %d", c)
	}
}
