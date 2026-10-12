package desktop

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const firefox = `[Desktop Entry]
Name=Firefox ESR
Exec=/usr/lib/firefox-esr/firefox-esr %u
Icon=firefox-esr
Type=Application
DBusActivatable=true
Actions=new-private-window;

[Desktop Action new-private-window]
Name=New Private Window
Exec=/usr/lib/firefox-esr/firefox-esr --private-window %u
`

func setup(t *testing.T) (home, sys string) {
	t.Helper()
	root := t.TempDir()
	home = filepath.Join(root, "home")
	sys = filepath.Join(root, "sys")
	t.Setenv("XDG_DATA_HOME", home)
	t.Setenv("XDG_DATA_DIRS", sys)
	_ = os.MkdirAll(filepath.Join(sys, "applications"), 0o755)
	_ = os.WriteFile(filepath.Join(sys, "applications", "firefox-esr.desktop"), []byte(firefox), 0o644)
	_ = os.WriteFile(filepath.Join(sys, "applications", "hidden.desktop"), []byte("[Desktop Entry]\nName=X\nExec=x\nType=Application\nNoDisplay=true\n"), 0o644)
	return home, sys
}

func TestSetUnset(t *testing.T) {
	home, _ := setup(t)
	if err := SetRoute("firefox-esr", "tunnel:vps", "/usr/local/bin/shunt"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(home, "applications", "firefox-esr.desktop"))
	got := string(b)
	for _, want := range []string{
		"Exec=/usr/local/bin/shunt run --via tunnel:vps -- /usr/lib/firefox-esr/firefox-esr %u",
		"Exec=/usr/local/bin/shunt run --via tunnel:vps -- /usr/lib/firefox-esr/firefox-esr --private-window %u",
		"X-Shunt-Route=tunnel:vps\nDBusActivatable=false\n[Desktop Action",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "DBusActivatable=true") {
		t.Error("D-Bus activation must be disabled")
	}

	// changing the route rewrites from the original, not our copy
	if err := SetRoute("firefox-esr", "direct", "shunt"); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(filepath.Join(home, "applications", "firefox-esr.desktop"))
	if strings.Count(string(b), "run --via") != 2 || !strings.Contains(string(b), "--via direct") {
		t.Errorf("double prefix or wrong route:\n%s", b)
	}

	list, _ := List()
	if len(list) != 1 || list[0].Route != "direct" || list[0].Name != "Firefox ESR" {
		t.Fatalf("list: %+v", list)
	}
	if err := Unset("firefox-esr"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(home, "applications", "firefox-esr.desktop")); !os.IsNotExist(err) {
		t.Error("override not removed")
	}
}

func TestOwnCustomEntryUntouched(t *testing.T) {
	home, _ := setup(t)
	own := filepath.Join(home, "applications", "firefox-esr.desktop")
	_ = os.MkdirAll(filepath.Dir(own), 0o755)
	_ = os.WriteFile(own, []byte("[Desktop Entry]\nName=Mine\nExec=ff\nType=Application\n"), 0o644)
	if err := SetRoute("firefox-esr", "direct", "shunt"); err == nil {
		t.Error("must not overwrite the user's own entry")
	}
	if err := Unset("firefox-esr"); err == nil {
		t.Error("must not delete the user's own entry")
	}
}

func TestOnline(t *testing.T) {
	for cats, want := range map[string]bool{
		"Network;WebBrowser;":           true,
		"GNOME;GTK;Email;":              true,
		"Utility;":                      false,
		"Network;X-Kali-05-sniff-spoof": false,
		"":                              false,
	} {
		if got := online(cats); got != want {
			t.Errorf("%q: got %v", cats, got)
		}
	}
}
