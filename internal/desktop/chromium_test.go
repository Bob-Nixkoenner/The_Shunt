package desktop

import (
	"os"
	"path/filepath"
	"testing"
)

func TestChromiumProfilesAndInstance(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, ".config", "google-chrome")
	if err := os.MkdirAll(filepath.Join(root, "Profile 2"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "Default"), 0o755); err != nil {
		t.Fatal(err)
	}
	ls := `{"profile":{"info_cache":{"Default":{"name":"test 1"},"Profile 2":{"name":"test 2"},"Gone":{"name":"x"},"../evil":{"name":"y"}}}}`
	if err := os.WriteFile(filepath.Join(root, "Local State"), []byte(ls), 0o644); err != nil {
		t.Fatal(err)
	}
	got := chromiumProfilesIn(home)
	if len(got) != 2 || got[0].Name != "test 1" || got[1].Dir != "Profile 2" || got[0].Browser != "chrome" {
		t.Fatalf("profiles %+v", got)
	}
	dir, err := ChromiumInstance(home, got[1], "Chrome test 2")
	if err != nil {
		t.Fatal(err)
	}
	if tgt, _ := os.Readlink(filepath.Join(dir, "Default")); tgt != filepath.Join(root, "Profile 2") {
		t.Errorf("link -> %q", tgt)
	}
	if _, err := ChromiumInstance(home, got[1], "Chrome test 2"); err != nil {
		t.Errorf("second call: %v", err)
	}
	if _, err := ChromiumInstance(home, got[0], "Chrome test 2"); err == nil {
		t.Error("an instance folder was handed to another profile")
	}
	if _, err := ChromiumInstance(home, ChromiumProfile{Browser: "chrome", Root: "/etc", Dir: "x"}, "evil"); err == nil {
		t.Error("unknown profile accepted")
	}
	if ChromiumBrowserOf("brave_brave") != "brave" || ChromiumBrowserOf("firefox") != "" || ChromiumBrowserOf("opera-gx_opera-gx") != "opera-gx" {
		t.Error("browser ids")
	}
}
