package splitstack

import (
	"os"
	"strings"
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/blocklist"
)

func TestSetFilterBlocksAndRecords(t *testing.T) {
	l, err := blocklist.Parse("ads", strings.NewReader("ads.example.com\n"))
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{}
	if got := e.blockedName("firefox.exe", "ads.example.com."); got != "" {
		t.Fatalf("no filter set, blocked by %q", got)
	}
	e.SetFilter(blocklist.NewFilter(map[string][]*blocklist.List{"normal": {l}}, nil), "normal")
	if got := e.blockedName("firefox.exe", "Ads.Example.com."); got != "ads" {
		t.Fatalf("blocked by %q, want ads", got)
	}
	if got := e.blockedName("firefox.exe", "fine.example.com."); got != "" {
		t.Fatalf("fine.example.com blocked by %q", got)
	}
	if len(e.recent) != 1 || e.recent[0].Name != "ads.example.com" || e.recent[0].List != "ads" || e.recent[0].Level != "normal" {
		t.Fatalf("recent: %+v", e.recent)
	}
	e.SetFilter(nil, "")
	if got := e.blockedName("firefox.exe", "ads.example.com."); got != "" {
		t.Fatalf("filter removed, blocked by %q", got)
	}
}

// A Wi-Fi profile with its own lists filters with those on that Wi-Fi only;
// an empty list switches the filter off there; other networks keep the
// config's lists (Android: DNS filter lists per Wi-Fi, ssid = hash id).
func TestNetworkBlocklists(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := dir + "/" + name
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ads, trk := write("ads", "ads.example.com\n"), write("trk", "trk.example.com\n")
	cfg := `{"default":"direct","direct_dns":"192.0.2.53",
		"blocklists":[{"name":"ads","path":"` + ads + `"}],
		"networks":[
			{"name":"wifi-a","link":"wifi","ssid":["aaaaaaaaaaaa"],"blocklists":[{"name":"trk","path":"` + trk + `"}]},
			{"name":"wifi-b","link":"wifi","ssid":["bbbbbbbbbbbb"],"blocklists":[]},
			{"name":"wifi","link":"wifi"}]}`
	c, err := parseConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{}
	if err := e.setRules(c); err != nil {
		t.Fatal(err)
	}
	check := func(ssid, name, want string) {
		t.Helper()
		e.mu.Lock()
		e.link, e.ssid = "wifi", ssid
		e.applyNetwork()
		e.mu.Unlock()
		if got := e.blockedName("app", name); got != want {
			t.Errorf("wifi %q: %s blocked by %q, want %q", ssid, name, got, want)
		}
	}
	check("", "ads.example.com.", "ads") // no id (no permission): the config's lists
	check("cccccccccccc", "ads.example.com.", "ads")
	check("aaaaaaaaaaaa", "trk.example.com.", "trk")
	check("aaaaaaaaaaaa", "ads.example.com.", "")
	check("bbbbbbbbbbbb", "ads.example.com.", "") // empty: no filter on this Wi-Fi
	e.SetFilter(blocklist.NewFilter(map[string][]*blocklist.List{"x": nil}, nil), "x")
	check("bbbbbbbbbbbb", "ads.example.com.", "") // not the platform's filter either
	check("", "ads.example.com.", "ads")
}

// Names and lists the user allows are never blocked, with their subdomains;
// an empty or missing allowlist does not stop the filter.
func TestAllowNamesAndLists(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := dir + "/" + name
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ads := write("ads", "||example.com^\ntracker.test\n")
	allow := write("allow", "# mine\n@@||good.example.com^\nshop.tracker.test\n")
	empty := write("empty", "# nothing\n")
	cfg := `{"default":"direct","direct_dns":"192.0.2.53",
		"blocklists":[{"name":"ads","path":"` + ads + `"}],
		"allow":["Ok.example.com", "not a name"],
		"allow_lists":[{"name":"allow","path":"` + allow + `"},{"name":"e","path":"` + empty + `"},{"name":"gone","path":"` + dir + `/missing"}]}`
	c, err := parseConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{}
	if err := e.setRules(c); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"x.example.com.":           "ads",
		"ok.example.com.":          "", // allowed by name
		"deep.ok.example.com.":     "", // and its subdomains
		"good.example.com.":        "", // allowed by list (@@||)
		"a.good.example.com.":      "",
		"tracker.test.":            "ads", // not allowed
		"shop.tracker.test.":       "",    // exact entry in the list
		"other.shop.tracker.test.": "",    // plain list entries are exact: not blocked at all
	} {
		if got := e.blockedName("app", name); got != want {
			t.Errorf("%s blocked by %q, want %q", name, got, want)
		}
	}
}
