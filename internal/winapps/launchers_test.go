package winapps

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
)

func TestLaunchers(t *testing.T) {
	dir := t.TempDir()
	var made []Shortcut
	brave := `C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe`
	s := &Source{Client: &fakeAPI{cfg: &config.Config{}}, Self: `C:\Program Files\The Shunt\shunt-desktop.exe`,
		LauncherDir: filepath.Join(dir, "cfg"), MenuDir: filepath.Join(dir, "menu"),
		Installed: func() []StartMenuProgram { return []StartMenuProgram{{"Brave", brave}} },
		Procs:     func() []string { return nil },
		Shortcut: func(sc Shortcut) error {
			made = append(made, sc)
			return os.WriteFile(sc.Path, []byte("lnk"), 0o644)
		}}
	id, err := s.Clone("brave.exe", "Brave  Bob", `--user-data-dir="C:\Users\b\ShuntProfiles\brave-bob"`, "tunnel:vps")
	if err != nil || id != "shunt-brave-bob" {
		t.Fatalf("clone: %q %v", id, err)
	}
	sc := made[0]
	if sc.Target != s.Self || sc.Args != `run --via tunnel:vps -- "`+brave+`" --user-data-dir="C:\Users\b\ShuntProfiles\brave-bob"` ||
		sc.Path != filepath.Join(dir, "menu", "Brave Bob.lnk") || sc.Icon != brave+",0" {
		t.Fatalf("shortcut %+v", sc)
	}
	if _, err := s.Clone("brave.exe", "Brave Bob", "", "direct"); err == nil {
		t.Error("same launcher twice")
	}
	for _, bad := range [][3]string{{"nope.exe", "X", ""}, {"brave.exe", "", ""}, {"brave.exe", "Y", `"open`}, {"brave.exe", "Z", "a\nb"}} {
		if _, err := s.Clone(bad[0], bad[1], bad[2], "direct"); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	l, _ := s.List()
	var b, prog = -1, -1
	for i, e := range l {
		switch e.ID {
		case id:
			b = i
		case "brave.exe":
			prog = i
		}
	}
	if b < 0 || l[b].Clone != "brave.exe" || l[b].Route != "tunnel:vps" || !strings.Contains(l[b].Exec, ` -- "`+brave+`"`) {
		t.Fatalf("launcher entry %+v", l)
	}
	if prog < 0 || l[prog].Chromium != "brave" {
		t.Fatalf("program entry %+v", l)
	}
	if err := s.SetRoute(id, "direct"); err != nil || len(made) != 2 || !strings.HasPrefix(made[1].Args, "run --via direct -- ") {
		t.Fatalf("new route: %v %+v", err, made)
	}
	if err := s.SetRoute(id, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(sc.Path); !os.IsNotExist(err) {
		t.Error("shortcut not removed")
	}
	if ls, _ := s.loadLaunchers(); len(ls) != 0 {
		t.Errorf("left: %+v", ls)
	}
}

func TestWinQuote(t *testing.T) {
	for in, want := range map[string]string{
		`C:\a\b.exe`: `C:\a\b.exe`, `C:\Program Files\x.exe`: `"C:\Program Files\x.exe"`,
		`a"b`: `"a\"b"`, `C:\dir with space\`: `"C:\dir with space\\"`, "": `""`,
	} {
		if got := winQuote(in); got != want {
			t.Errorf("%q: %s, want %s", in, got, want)
		}
	}
}
