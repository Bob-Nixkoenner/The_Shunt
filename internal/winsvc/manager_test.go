package winsvc

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/api"
	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/Bob-Nixkoenner/the_shunt/internal/splitstack"
)

func key(b byte) string {
	return base64.StdEncoding.EncodeToString([]byte(strings.Repeat(string([]byte{b}), 32)))
}

func wgConf() string {
	return "[Interface]\nPrivateKey = " + key(1) + "\nAddress = 10.9.0.2/32\nDNS = 10.9.0.1\n\n[Peer]\nPublicKey = " + key(2) +
		"\nAllowedIPs = 0.0.0.0/0\nEndpoint = 192.0.2.1:51820\nPersistentKeepalive = 25\n"
}

type rec struct {
	rules    []string
	restarts int
}

func newMgr(t *testing.T) (*Manager, *rec) {
	t.Helper()
	r := &rec{}
	m := &Manager{Dir: t.TempDir(), StatsPath: "stats.json",
		SetRules: func(js string) error { r.rules = append(r.rules, js); return nil },
		Restart:  func() { r.restarts++ }}
	if _, _, err := m.Load(); err != nil {
		t.Fatal(err)
	}
	return m, r
}

func TestDefaultConfigAndImport(t *testing.T) {
	m, r := newMgr(t)
	if def, _ := m.Summary(); def != "direct" {
		t.Fatalf("default %q", def)
	}
	if _, err := os.Stat(filepath.Join(m.Dir, "shunt.toml")); err != nil {
		t.Fatal(err)
	}
	warn, err := m.ImportTunnel(api.TunnelImport{Name: "home", Conf: wgConf()})
	if err != nil {
		t.Fatal(err)
	}
	_ = warn
	if r.restarts != 1 {
		t.Fatalf("a new tunnel needs a restart, got %d", r.restarts)
	}
	v, err := m.View()
	if err != nil || len(v.Tunnels) != 1 || v.Tunnels[0].Name != "home" || v.Tunnels[0].Endpoint != "192.0.2.1:51820" || v.Tunnels[0].Addresses[0] != "10.9.0.2/32" {
		t.Fatalf("view: %+v %v", v.Tunnels, err)
	}
	if strings.Contains(v.Raw, key(1)) {
		t.Fatal("private key in the config text")
	}
	if _, err := m.ImportTunnel(api.TunnelImport{Name: "home", Conf: wgConf()}); err == nil {
		t.Fatal("duplicate tunnel accepted")
	}
	if _, err := m.ImportTunnel(api.TunnelImport{Name: "Bad Name", Conf: wgConf()}); err == nil {
		t.Fatal("bad name accepted")
	}
	// deleting: route in use first
	cfg := v.Config
	cfg.Daemon.DefaultRoute = "tunnel:home"
	raw, _ := cfg.Encode()
	if _, err := m.Save(raw, v.Version); err != nil {
		t.Fatal(err)
	}
	if err := m.DeleteTunnel("home"); err == nil {
		t.Fatal("deleted the default route's tunnel")
	}
	cfg.Daemon.DefaultRoute = "direct"
	raw, _ = cfg.Encode()
	if _, err := m.Save(raw, ""); err != nil {
		t.Fatal(err)
	}
	if err := m.DeleteTunnel("home"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(m.Dir, "tunnels", "home.conf")); err == nil {
		t.Fatal("tunnel file left behind")
	}
}

func TestRuleChangeAppliesLive(t *testing.T) {
	m, r := newMgr(t)
	if _, err := m.ImportTunnel(api.TunnelImport{Name: "home", Conf: wgConf()}); err != nil {
		t.Fatal(err)
	}
	// engine restarted with the tunnel: pretend, as the service would
	if _, _, err := m.Load(); err != nil {
		t.Fatal(err)
	}
	r.restarts = 0
	v, _ := m.View()
	raw := v.Raw + "\n[[rule]]\nname = \"ff\"\napp = [\"firefox\", \"exe:C:\\\\Tools\\\\Curl.exe\"]\nroute = \"tunnel:home\"\n" +
		"[[rule]]\nname = \"ssh\"\ncidr = [\"10.0.0.0/8\"]\nport = [\"tcp/22\"]\nroute = \"block\"\n"
	warn, err := m.Save([]byte(raw), v.Version)
	if err != nil {
		t.Fatal(err)
	}
	if len(warn) != 0 || r.restarts != 0 || len(r.rules) != 1 {
		t.Fatalf("warn=%v restarts=%d applied=%d", warn, r.restarts, len(r.rules))
	}
	var js struct {
		Apps  map[string]string
		Rules []struct {
			Name, Route string
			CIDR, Ports []string
		}
		StatsPath string `json:"stats_path"`
	}
	if err := json.Unmarshal([]byte(r.rules[0]), &js); err != nil {
		t.Fatal(err)
	}
	if js.Apps["firefox.exe"] != "tunnel:home" || js.Apps[`c:\tools\curl.exe`] != "tunnel:home" || len(js.Rules) != 1 || js.Rules[0].Route != "block" || js.StatsPath != "stats.json" {
		t.Fatalf("engine config: %s", r.rules[0])
	}
	// stale version is refused, file untouched
	if _, err := m.Save([]byte(raw), v.Version); err != ErrConflict {
		t.Fatalf("conflict not detected: %v", err)
	}
	// a bad route is refused before anything is written
	bad := raw + "\n[[rule]]\napp = [\"x\"]\nroute = \"tunnel:nope\"\n"
	before, _ := os.ReadFile(filepath.Join(m.Dir, "shunt.toml"))
	if _, err := m.Save([]byte(bad), ""); err == nil {
		t.Fatal("unknown tunnel accepted")
	}
	after, _ := os.ReadFile(filepath.Join(m.Dir, "shunt.toml"))
	if string(before) != string(after) {
		t.Fatal("file changed by a refused save")
	}
	if _, err := os.Stat(filepath.Join(m.Dir, "shunt.toml.bak")); err != nil {
		t.Fatal("no backup")
	}
}

func TestTranslateWarnsAndDisables(t *testing.T) {
	c, err := config.Parse(`
[daemon]
default_route = "tunnel:off"
[tunnel.off]
config = "tunnels/off.conf"
disabled = true
[tunnel.ov]
config = "tunnels/ov.ovpn"
driver = "openvpn"
[group.x]
[[rule]]
name = "g"
group = ["x"]
route = "direct"
[[rule]]
name = "l"
app = ["foo"]
route = "link:wifi"
`)
	if err == nil {
		_, _, err = Translate(c, func(string) ([]byte, error) { return []byte("x"), nil })
	}
	if err != nil {
		t.Fatalf("link route: %v", err)
	}
	c.Rules = c.Rules[:1]
	js, warn, err := Translate(c, func(string) ([]byte, error) { return []byte("x"), nil })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(js, `"default":"block"`) {
		t.Fatalf("disabled tunnel must block: %s", js)
	}
	joined := strings.Join(warn, "|")
	if !strings.Contains(joined, "OpenVPN is not available") || !strings.Contains(joined, "groups are not available") {
		t.Fatalf("warnings: %v", warn)
	}
}

func TestImportTailscale(t *testing.T) {
	m, r := newMgr(t)
	tsConf := "login_server = http://headscale.example:8080\nauth_key = hskey-auth-abc\nexit_node = 100.64.0.1\n"
	if _, err := m.ImportTunnel(api.TunnelImport{Name: "hs", Conf: "login_server = nonsense\nauth_key = x\n"}); err == nil {
		t.Fatal("bad login_server accepted")
	}
	if _, err := m.ImportTunnel(api.TunnelImport{Name: "hs", Conf: tsConf}); err != nil {
		t.Fatal(err)
	}
	if r.restarts != 1 {
		t.Fatalf("a new tunnel needs a restart, got %d", r.restarts)
	}
	if _, err := os.Stat(filepath.Join(m.Dir, "tunnels", "hs.ts")); err != nil {
		t.Fatal(err)
	}
	v, err := m.View()
	if err != nil || len(v.Tunnels) != 1 || v.Tunnels[0].Type != "tailscale" || v.Tunnels[0].Endpoint != "headscale.example:8080" {
		t.Fatalf("view: %+v %v", v.Tunnels, err)
	}
	if strings.Contains(v.Raw, "hskey-auth-abc") {
		t.Fatal("auth key in the config text")
	}
	raw, err := os.ReadFile(filepath.Join(m.Dir, "shunt.toml"))
	if err != nil {
		t.Fatal(err)
	}
	_, js, _, err := m.build(raw, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(js, `"type":"tailscale"`) || !strings.Contains(js, `"work_dir"`) {
		t.Fatalf("engine config: %s", js)
	}
}

func TestTranslateFilterScopes(t *testing.T) {
	c, err := config.Parse("[daemon]\ndefault_route = \"direct\"\n[[network]]\nname = \"cafe\"\nssid = [\"cafe\"]\ndefault_route = \"direct\"\ndns_filter = \"paranoid\"\n")
	if err != nil {
		t.Fatal(err)
	}
	_, warn, err := Translate(c, func(string) ([]byte, error) { return nil, nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(warn) != 1 || !strings.Contains(warn[0], "DNS filter level of single tunnels") {
		t.Fatalf("warnings: %q", warn)
	}
	c, _ = config.Parse("[dns_filter]\ndefault = \"low\"\n[daemon]\ndefault_route = \"direct\"\n")
	if _, warn, _ = Translate(c, func(string) ([]byte, error) { return nil, nil }); len(warn) != 0 {
		t.Fatalf("default level only should not warn: %q", warn)
	}
}

func TestTranslateTor(t *testing.T) {
	c, err := config.Parse("[daemon]\ndefault_route = \"tunnel:t\"\n[tunnel.t]\ndriver = \"tor\"\nbridges = [\"snowflake\"]\n")
	if err != nil {
		t.Fatal(err)
	}
	js, warn, err := translate(c, func(string) ([]byte, error) { return nil, nil }, func(string, config.Tunnel) string { return "127.0.0.1:9150" })
	if err != nil || len(warn) != 0 {
		t.Fatal(err, warn)
	}
	for _, want := range []string{`"type":"tor"`, `socks = 127.0.0.1:9150`, `"tor.exe":"direct"`} {
		if !strings.Contains(js, want) {
			t.Errorf("%s missing in %s", want, js)
		}
	}
	// without tor.exe the tunnel exists but nothing listens: down, no leak
	js, warn, _ = translate(c, nil, nil)
	if !strings.Contains(js, `127.0.0.1:9`) || len(warn) == 0 {
		t.Errorf("no tor: %s %v", js, warn)
	}
	if err := splitstack.CheckConfig(js); err != nil {
		t.Error(err)
	}
}
