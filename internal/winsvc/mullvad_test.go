package winsvc

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/api"
)

const mvRelays4 = `{"locations":{"de-fra":{"country":"Germany","city":"Frankfurt"},"se-got":{"country":"Sweden","city":"Gothenburg"},"ch-zrh":{"country":"Switzerland","city":"Zurich"},"nl-ams":{"country":"Netherlands","city":"Amsterdam"}},
"wireguard":{"ipv4_gateway":"10.64.0.1","relays":[
{"hostname":"de-fra-wg-001","location":"de-fra","active":true,"provider":"A","ipv4_addr_in":"198.51.100.1","public_key":"ofyfRvMPB0PPIGGItNL+5tNdvTKXuWye5CfjPgPNvQ8=","weight":100,"include_in_country":true},
{"hostname":"se-got-wg-001","location":"se-got","active":true,"provider":"B","ipv4_addr_in":"198.51.100.3","public_key":"ofyfRvMPB0PPIGGItNL+5tNdvTKXuWye5CfjPgPNvQ8=","weight":50,"include_in_country":true},
{"hostname":"ch-zrh-wg-001","location":"ch-zrh","active":true,"provider":"C","ipv4_addr_in":"198.51.100.4","public_key":"ofyfRvMPB0PPIGGItNL+5tNdvTKXuWye5CfjPgPNvQ8=","weight":50,"include_in_country":true},
{"hostname":"nl-ams-wg-001","location":"nl-ams","active":true,"provider":"A","ipv4_addr_in":"198.51.100.5","public_key":"ofyfRvMPB0PPIGGItNL+5tNdvTKXuWye5CfjPgPNvQ8=","weight":50,"include_in_country":true}]}}`

// a fake Mullvad; deleted counts the devices removed
func fakeMullvad(t *testing.T, deleted *int) *httptest.Server {
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && r.URL.Path == "/auth/v1/token":
			_, _ = w.Write([]byte(`{"access_token":"tok"}`))
		case r.Method == "POST" && r.URL.Path == "/accounts/v1/devices":
			n++
			_, _ = fmt.Fprintf(w, `{"id":"dev-%d","name":"fox %d","ipv4_address":"10.70.1.%d/32","ipv6_address":"fc00::%d/128"}`, n, n, n+1, n+1)
		case r.Method == "DELETE":
			*deleted++
			w.WriteHeader(204)
		case r.URL.Path == "/public/relays/wireguard/v2":
			_, _ = w.Write([]byte(mvRelays4))
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// Login, connect, switch the exit in place, chains in ONE restart each, logout.
func TestMullvadWindowsFlow(t *testing.T) {
	deleted := 0
	srv := fakeMullvad(t, &deleted)
	m, r := newMgr(t)
	m.mv.client.Base = srv.URL
	if err := m.MullvadConnect(api.MullvadConnect{Country: "de"}); err == nil {
		t.Fatal("connect without login accepted")
	}
	if err := m.MullvadLogin("", "12345"); err == nil {
		t.Fatal("short account accepted")
	}
	if err := m.MullvadLogin("a", "1111 2222 3333 4444"); err != nil {
		t.Fatal(err)
	}
	if err := m.MullvadLogin("b", "5555666677778888"); err != nil {
		t.Fatal(err)
	}
	if err := m.MullvadLogin("c", "1111222233334444"); err == nil {
		t.Fatal("same account twice accepted")
	}
	st, _ := m.MullvadStatus()
	if !st.LoggedIn || len(st.Accounts) != 2 || st.Accounts[0].Account != "••••4444" {
		t.Fatalf("%+v", st)
	}
	if b, _ := os.ReadFile(m.mullvadPath()); !strings.Contains(string(b), "private_key") || filepath.Dir(m.mullvadPath()) != m.tunnelDir() {
		t.Fatal("store missing or not in the tunnel folder")
	}
	if err := m.MullvadConnect(api.MullvadConnect{Tunnel: "mullvad", Country: "de"}); err == nil {
		t.Fatal("two accounts, none named: must ask")
	}
	if err := m.MullvadConnect(api.MullvadConnect{Tunnel: "mullvad", Account: "a", Country: "de"}); err != nil {
		t.Fatal(err)
	}
	before := r.restarts
	if err := m.MullvadConnect(api.MullvadConnect{Tunnel: "mullvad", City: "se-got"}); err != nil { // exit switch
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(m.tunnelDir(), "mullvad.conf"))
	if !strings.Contains(string(b), "198.51.100.3:51820") || r.restarts != before+1 {
		t.Fatalf("switch: restarts %d->%d\n%s", before, r.restarts, b)
	}
	if err := m.MullvadConnect(api.MullvadConnect{Tunnel: "mullvad", Account: "b", City: "se-got"}); err == nil {
		t.Fatal("account change on a live tunnel accepted")
	}

	// a chain: three hops, one change, one restart
	before = r.restarts
	if err := m.MullvadChain(api.MullvadChain{Name: "ch", Hops: 3, Entry: "de", Exit: "nl", Via: "tunnel:mullvad"}); err != nil {
		t.Fatal(err)
	}
	if r.restarts != before+1 {
		t.Fatalf("a chain must restart once, got %d", r.restarts-before)
	}
	cfg := m.Current()
	if cfg.Tunnels["ch1"].Via != "tunnel:mullvad" || cfg.Tunnels["ch2"].Via != "tunnel:ch1" || cfg.Tunnels["ch3"].Via != "tunnel:ch2" {
		t.Fatalf("via: %+v", cfg.Tunnels)
	}
	conf := func(n string) string { b, _ := os.ReadFile(filepath.Join(m.tunnelDir(), n+".conf")); return string(b) }
	if !strings.Contains(conf("ch1"), "MTU = 1340") || !strings.Contains(conf("ch3"), "MTU = 1280") {
		t.Fatalf("MTU per hop:\n%s\n%s", conf("ch1"), conf("ch3"))
	}
	if err := m.MullvadChain(api.MullvadChain{Name: "ch", Hops: 2}); err == nil {
		t.Fatal("name clash accepted")
	}
	if err := m.MullvadChainDelete("nope"); err == nil {
		t.Fatal("unknown chain accepted")
	}
	before = r.restarts
	if err := m.MullvadChainDelete("ch"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(m.tunnelDir(), "ch1.conf")); err == nil || r.restarts != before+1 || len(m.Current().Tunnels) != 1 {
		t.Fatalf("chain not gone in one change: %v %d", err, r.restarts-before)
	}

	// a rule on a tunnel keeps the login in place
	raw, _ := os.ReadFile(m.path())
	if _, err := m.Save([]byte(strings.TrimRight(string(raw), "\n")+"\n\n[[rule]]\nname = \"x\"\napp = [\"x\"]\nroute = \"tunnel:mullvad\"\n"), ""); err != nil {
		t.Fatal(err)
	}
	if err := m.MullvadLogout("a"); err == nil || !strings.Contains(err.Error(), "rule") {
		t.Fatalf("logout with a rule on the tunnel: %v", err)
	}
	if err := m.MullvadLogout("a"); err == nil {
		t.Fatal("second try must fail the same way")
	}
	raw, _ = os.ReadFile(m.path())
	if _, err := m.Save([]byte(strings.Split(string(raw), "[[rule]]")[0]), ""); err != nil {
		t.Fatal(err)
	}
	if err := m.MullvadLogout("a"); err != nil {
		t.Fatal(err)
	}
	if err := m.MullvadLogout("b"); err != nil {
		t.Fatal(err)
	}
	if deleted != 2 {
		t.Fatalf("devices removed at Mullvad: %d", deleted)
	}
	if st, _ = m.MullvadStatus(); st.LoggedIn || len(m.Current().Tunnels) != 0 {
		t.Fatalf("%+v %v", st, m.Current().Tunnels)
	}
	if _, err := os.Stat(m.mullvadPath()); err == nil {
		t.Fatal("store left behind")
	}
}
