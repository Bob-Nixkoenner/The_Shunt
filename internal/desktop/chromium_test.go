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

func TestChromiumWindows(t *testing.T) {
	home := t.TempDir()
	local, roaming := filepath.Join(home, "Local"), filepath.Join(home, "Roaming")
	defer func(g string, a func() (string, string)) { goos, appData = g, a }(goos, appData)
	goos, appData = "windows", func() (string, string) { return local, roaming }
	for _, r := range []string{filepath.Join(local, "BraveSoftware", "Brave-Browser", "User Data"), filepath.Join(roaming, "Opera Software", "Opera GX Stable")} {
		if err := os.MkdirAll(filepath.Join(r, "Default"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(r, "Local State"), []byte(`{"profile":{"info_cache":{"Default":{"name":"Bob"}}}}`), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got := chromiumProfilesIn(home)
	if len(got) != 2 || got[0].Browser != "brave" || got[1].Browser != "opera-gx" || got[0].Name != "Bob" {
		t.Fatalf("profiles %+v", got)
	}
	if _, err := ChromiumInstance(home, got[0], "Brave Bob"); err != ErrSharedProfile {
		t.Errorf("shared profile on Windows: %v", err)
	}
	for path, want := range map[string]string{
		`C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe`: "brave",
		`C:\Program Files\Google\Chrome\Application\chrome.exe`:              "chrome",
		`C:\Users\b\AppData\Local\Chromium\Application\chrome.exe`:           "chromium",
		`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`:       "edge",
		`C:\Users\b\AppData\Local\Programs\Opera GX\opera.exe`:               "opera-gx",
		`C:\Users\b\AppData\Local\Programs\Opera\launcher.exe`:               "opera",
		`C:\Program Files\Mozilla Firefox\firefox.exe`:                       "",
	} {
		if got := ChromiumBrowserOfExe(path); got != want {
			t.Errorf("%s: %q, want %q", path, got, want)
		}
	}
}
