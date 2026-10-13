package desktop

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFirefoxProfiles(t *testing.T) {
	root := filepath.Join(t.TempDir(), "firefox")
	for _, d := range []string{"a.default", "b.Profil 1", "c.old", "Profile Groups"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	ini := "[Profile1]\r\nName=default-release\r\nIsRelative=1\r\nPath=a.default\r\n\r\n[Profile0]\nName=old one\nIsRelative=1\nPath=c.old\n[Profile2]\nName=gone\nPath=missing\n"
	if err := os.WriteFile(filepath.Join(root, "profiles.ini"), []byte(ini), 0o644); err != nil {
		t.Fatal(err)
	}
	// newer profile manager: names in a database (and its write-ahead log)
	for _, f := range []string{"wal.sqlite", "wal.sqlite-wal"} {
		b, err := os.ReadFile(filepath.Join("..", "sqlitelite", "testdata", f))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "Profile Groups", "x"+f[3:]), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got := map[string]string{}
	for _, p := range firefoxProfilesIn([]string{root, filepath.Join(root, "nothing-here")}) {
		got[filepath.Base(p.Path)] = p.Name
	}
	want := map[string]string{"a.default": "privat", "b.Profil 1": "SM", "c.old": "old one"}
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %q, want %q", k, got[k], v)
		}
	}
}
