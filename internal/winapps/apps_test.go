package winapps

import (
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/api"
	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
)

type fakeAPI struct {
	cfg  *config.Config
	puts int
}

func (f *fakeAPI) Do(method, path string, in, out any) error {
	switch method + " " + path {
	case "GET /v1/config":
		*(out.(*api.ConfigView)) = api.ConfigView{Config: f.cfg, Version: "v"}
	case "PUT /v1/config":
		f.cfg = in.(api.ConfigSave).Config
		f.puts++
	}
	return nil
}

func TestListAndSet(t *testing.T) {
	f := &fakeAPI{cfg: &config.Config{Tunnels: map[string]config.Tunnel{"home": {}}}}
	s := &Source{Client: f, Installed: func() []StartMenuProgram {
		return []StartMenuProgram{{"Mozilla Firefox", `C:\Program Files\Mozilla Firefox\firefox.exe`}, {"Uninstall Foo", `C:\Foo\unins000.exe`},
			{"Notepad++", `C:\Program Files\Notepad++\notepad++.exe`}}
	}, Procs: func() []string {
		return []string{`C:\Program Files\Mozilla Firefox\firefox.exe`, `C:\Windows\System32\svchost.exe`, `C:\Windows\explorer.exe`, `C:\Tools\Curl.exe`, `C:\Tools\curl.exe`}
	}}
	l, err := s.List()
	if err != nil || len(l) != 4 || l[0].ID != "curl.exe" || l[2].ID != "firefox.exe" || l[2].Name != "Mozilla Firefox" || l[2].Route != "" || l[3].ID != "notepad++.exe" {
		t.Fatalf("list: %+v %v", l, err)
	}
	if err := s.SetRoute("Firefox.exe", "tunnel:home"); err != nil {
		t.Fatal(err)
	}
	if len(f.cfg.Rules) != 1 || f.cfg.Rules[0].App[0] != "firefox.exe" || f.cfg.Rules[0].Route != "tunnel:home" {
		t.Fatalf("rules: %+v", f.cfg.Rules)
	}
	if err := s.SetRoute("firefox.exe", "block"); err != nil || len(f.cfg.Rules) != 1 || f.cfg.Rules[0].Route != "block" {
		t.Fatalf("update: %+v %v", f.cfg.Rules, err)
	}
	l, _ = s.List()
	for _, e := range l {
		if e.ID == "firefox.exe" && e.Route != "block" {
			t.Fatalf("route not shown: %+v", e)
		}
	}
	// a rule for a program that does not run still shows up
	_ = s.SetRoute("gone.exe", "direct")
	s.cached = nil
	l, _ = s.List()
	if len(l) != 5 {
		t.Fatalf("ruled program missing: %+v", l)
	}
	if err := s.SetRoute("firefox.exe", ""); err != nil || len(f.cfg.Rules) != 1 {
		t.Fatalf("remove: %+v %v", f.cfg.Rules, err)
	}
	if err := s.SetRoute(`..\evil.exe`, "direct"); err == nil {
		t.Fatal("path accepted as program name")
	}
}
