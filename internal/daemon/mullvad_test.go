package daemon

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/api"
)

const mvRelays = `{"locations":{"de-fra":{"country":"Germany","city":"Frankfurt"},"se-got":{"country":"Sweden","city":"Gothenburg"}},
"wireguard":{"ipv4_gateway":"10.64.0.1","relays":[
{"hostname":"de-fra-wg-001","location":"de-fra","active":true,"ipv4_addr_in":"198.51.100.1","public_key":"ofyfRvMPB0PPIGGItNL+5tNdvTKXuWye5CfjPgPNvQ8=","weight":100,"include_in_country":true},
{"hostname":"se-got-wg-001","location":"se-got","active":true,"ipv4_addr_in":"198.51.100.3","public_key":"ofyfRvMPB0PPIGGItNL+5tNdvTKXuWye5CfjPgPNvQ8=","weight":50,"include_in_country":true}]}}`

// Login, connect, switch the exit in place, log out: against a fake Mullvad.
func TestMullvadFlow(t *testing.T) {
	var deleted bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "POST /auth/v1/token":
			_, _ = w.Write([]byte(`{"access_token":"tok"}`))
		case "POST /accounts/v1/devices":
			_, _ = w.Write([]byte(`{"id":"dev-1","name":"happy fox","ipv4_address":"10.70.1.2/32","ipv6_address":"fc00::2/128"}`))
		case "DELETE /accounts/v1/devices/dev-1":
			deleted = true
			w.WriteHeader(204)
		case "GET /public/relays/wireguard/v2":
			_, _ = w.Write([]byte(mvRelays))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	d, _ := testDaemon(t, "[daemon]\nsocket = \"/nonexistent/s.sock\"\ndefault_route = \"direct\"\n[dns]\ndisabled = true\n")
	d.mv.client.Base = srv.URL
	if err := d.reload("shunt"); err != nil {
		t.Fatal(err)
	}
	if err := d.MullvadConnect(api.MullvadConnect{Country: "de"}); err == nil {
		t.Fatal("connect without login accepted")
	}
	if err := d.MullvadLogin("", "12345"); err == nil {
		t.Fatal("short account accepted")
	}
	if err := d.MullvadLogin("", "1234 5678 9012 3456"); err != nil {
		t.Fatal(err)
	}
	if err := d.MullvadLogin("", "1234567890123456"); err == nil {
		t.Fatal("second login accepted")
	}
	if fi, err := os.Stat(d.mullvadPath()); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatal("store must be mode 600", err)
	}
	st, _ := d.MullvadStatus()
	if !st.LoggedIn || len(st.Accounts) != 1 || st.Accounts[0].Account != "••••3456" || st.Accounts[0].Device != "happy fox" {
		t.Fatalf("%+v", st)
	}
	if b, _ := os.ReadFile(d.mullvadPath()); !strings.Contains(string(b), "private_key") {
		t.Fatal("key not stored")
	}

	if err := d.MullvadConnect(api.MullvadConnect{Tunnel: "mullvad", Country: "de"}); err != nil {
		t.Fatal(err)
	}
	st, _ = d.MullvadStatus()
	if len(st.Exits) != 1 || st.Exits[0].Hostname != "de-fra-wg-001" {
		t.Fatalf("%+v", st)
	}
	// switch the exit of the same tunnel
	if err := d.MullvadConnect(api.MullvadConnect{Tunnel: "mullvad", City: "se-got"}); err != nil {
		t.Fatal(err)
	}
	st, _ = d.MullvadStatus()
	if len(st.Exits) != 1 || st.Exits[0].Country != "Sweden" {
		t.Fatalf("%+v", st)
	}
	b, err := os.ReadFile(d.tunnelDir() + "/mullvad.conf")
	if err != nil || !strings.Contains(string(b), "198.51.100.3:51820") {
		t.Fatalf("file not switched: %v\n%s", err, b)
	}
	// a second tunnel on another exit; a name that is not ours is refused
	if err := d.MullvadConnect(api.MullvadConnect{Tunnel: "mv2", Hostname: "de-fra-wg-001"}); err != nil {
		t.Fatal(err)
	}
	if err := d.MullvadConnect(api.MullvadConnect{Tunnel: "nope", Country: "xx"}); err == nil {
		t.Fatal("unknown country accepted")
	}
	if err := d.MullvadLogout(""); err != nil {
		t.Fatal(err)
	}
	if !deleted {
		t.Fatal("device not deleted at Mullvad")
	}
	if _, err := os.Stat(d.mullvadPath()); err == nil {
		t.Fatal("store left behind")
	}
	if st, _ = d.MullvadStatus(); st.LoggedIn || len(d.cfg.Tunnels) != 0 {
		t.Fatalf("%+v %v", st, d.cfg.Tunnels)
	}
}

// Two accounts, a chain through both, MTU per hop, partial logout, old file format.
func TestMullvadAccountsChain(t *testing.T) {
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && r.URL.Path == "/auth/v1/token":
			_, _ = w.Write([]byte(`{"access_token":"tok"}`))
		case r.Method == "POST" && r.URL.Path == "/accounts/v1/devices":
			n++
			_, _ = fmt.Fprintf(w, `{"id":"dev-%d","name":"fox %d","ipv4_address":"10.70.1.%d/32","ipv6_address":"fc00::%d/128"}`, n, n, n+1, n+1)
		case r.Method == "DELETE":
			w.WriteHeader(204)
		case r.URL.Path == "/public/relays/wireguard/v2":
			_, _ = w.Write([]byte(mvRelays))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	d, _ := testDaemon(t, "[daemon]\nsocket = \"/nonexistent/s.sock\"\ndefault_route = \"direct\"\n[dns]\ndisabled = true\n")
	d.mv.client.Base = srv.URL
	if err := d.reload("shunt"); err != nil {
		t.Fatal(err)
	}
	if err := d.MullvadLogin("a", "1111222233334444"); err != nil {
		t.Fatal(err)
	}
	if err := d.MullvadLogin("b", "5555666677778888"); err != nil {
		t.Fatal(err)
	}
	if err := d.MullvadLogin("c", "1111 2222 3333 4444"); err == nil {
		t.Fatal("same account twice accepted")
	}
	if err := d.MullvadConnect(api.MullvadConnect{Tunnel: "hop1", Country: "de"}); err == nil {
		t.Fatal("two accounts, none named: must ask")
	}
	if err := d.MullvadConnect(api.MullvadConnect{Tunnel: "hop1", Account: "a", Country: "de"}); err != nil {
		t.Fatal(err)
	}
	if err := d.MullvadConnect(api.MullvadConnect{Tunnel: "hop2", Account: "b", Country: "se", Via: "tunnel:hop1"}); err != nil {
		t.Fatal(err)
	}
	if err := d.MullvadConnect(api.MullvadConnect{Tunnel: "hop3", Account: "a", Country: "de", Via: "tunnel:hop2"}); err != nil {
		t.Fatal(err)
	}
	conf := func(n string) string { b, _ := os.ReadFile(d.tunnelDir() + "/" + n + ".conf"); return string(b) }
	if strings.Contains(conf("hop1"), "MTU") || !strings.Contains(conf("hop2"), "MTU = 1340") || !strings.Contains(conf("hop3"), "MTU = 1280") {
		t.Fatalf("MTU per hop wrong:\n%s\n%s\n%s", conf("hop1"), conf("hop2"), conf("hop3"))
	}
	if !strings.Contains(conf("hop2"), "10.70.1.3/32") { // account b's own address
		t.Fatal("hop2 does not use account b")
	}
	// switching the exit keeps account, via and MTU
	if err := d.MullvadConnect(api.MullvadConnect{Tunnel: "hop2", City: "de-fra"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(conf("hop2"), "MTU = 1340") || !strings.Contains(conf("hop2"), "10.70.1.3/32") || !strings.Contains(conf("hop2"), "198.51.100.1:51820") {
		t.Fatalf("switch lost settings:\n%s", conf("hop2"))
	}
	if err := d.MullvadConnect(api.MullvadConnect{Tunnel: "hop2", Account: "a", City: "de-fra"}); err == nil {
		t.Fatal("account change on a live tunnel accepted")
	}
	// the chain hop1 (a) <- hop2 (b) <- hop3 (a): outermost first
	if err := d.MullvadLogout("b"); err == nil {
		t.Fatal("hop2 is used by hop3: logout of b must stop")
	}
	if err := d.MullvadLogout("a"); err == nil || !strings.Contains(err.Error(), "hop1") {
		t.Fatalf("a must stop at hop1 (hop2 runs through it): %v", err) // hop3 is gone by now
	}
	if err := d.MullvadLogout("b"); err != nil { // hop2 is free now
		t.Fatal(err)
	}
	if err := d.MullvadLogout("a"); err != nil {
		t.Fatal(err)
	}
	if st, _ := d.MullvadStatus(); st.LoggedIn || len(d.cfg.Tunnels) != 0 {
		t.Fatalf("%+v %v", st, d.cfg.Tunnels)
	}
}

// The first version stored one login at the top level of mullvad.json.
func TestMullvadOldStoreMigrates(t *testing.T) {
	d, _ := testDaemon(t, "[daemon]\nsocket = \"/nonexistent/s.sock\"\ndefault_route = \"direct\"\n[dns]\ndisabled = true\n")
	old := `{"account":"1234567890123456","device_id":"dev-1","device_name":"happy fox","private_key":"k","ipv4":"10.70.1.2/32","ipv6":"fc00::2/128","exits":{"mullvad":{"tunnel":"mullvad","hostname":"de-fra-wg-001","country":"Germany","city":"Frankfurt"}}}`
	if err := os.WriteFile(d.mullvadPath(), []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := d.mullvadLoad()
	if err != nil || s == nil || s.Accounts["main"] == nil || s.Accounts["main"].DeviceID != "dev-1" || s.Exits["mullvad"].Account != "main" || s.Account != "" {
		t.Fatalf("%+v %v", s, err)
	}
}

const mvRelays4 = `{"locations":{"de-fra":{"country":"Germany","city":"Frankfurt"},"se-got":{"country":"Sweden","city":"Gothenburg"},"ch-zrh":{"country":"Switzerland","city":"Zurich"},"nl-ams":{"country":"Netherlands","city":"Amsterdam"}},
"wireguard":{"ipv4_gateway":"10.64.0.1","relays":[
{"hostname":"de-fra-wg-001","location":"de-fra","active":true,"provider":"A","ipv4_addr_in":"198.51.100.1","public_key":"ofyfRvMPB0PPIGGItNL+5tNdvTKXuWye5CfjPgPNvQ8=","weight":100,"include_in_country":true},
{"hostname":"se-got-wg-001","location":"se-got","active":true,"provider":"B","ipv4_addr_in":"198.51.100.3","public_key":"ofyfRvMPB0PPIGGItNL+5tNdvTKXuWye5CfjPgPNvQ8=","weight":50,"include_in_country":true},
{"hostname":"ch-zrh-wg-001","location":"ch-zrh","active":true,"provider":"C","ipv4_addr_in":"198.51.100.4","public_key":"ofyfRvMPB0PPIGGItNL+5tNdvTKXuWye5CfjPgPNvQ8=","weight":50,"include_in_country":true},
{"hostname":"nl-ams-wg-001","location":"nl-ams","active":true,"provider":"A","ipv4_addr_in":"198.51.100.5","public_key":"ofyfRvMPB0PPIGGItNL+5tNdvTKXuWye5CfjPgPNvQ8=","weight":50,"include_in_country":true}]}}`

// The chain builder: hops in different countries, two accounts in turn, each
// hop through the one before; a name clash stops it before anything is made.
func TestMullvadChainBuilder(t *testing.T) {
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && r.URL.Path == "/auth/v1/token":
			_, _ = w.Write([]byte(`{"access_token":"tok"}`))
		case r.Method == "POST" && r.URL.Path == "/accounts/v1/devices":
			n++
			_, _ = fmt.Fprintf(w, `{"id":"dev-%d","name":"fox %d","ipv4_address":"10.70.1.%d/32","ipv6_address":"fc00::%d/128"}`, n, n, n+1, n+1)
		case r.Method == "DELETE":
			w.WriteHeader(204)
		case r.URL.Path == "/public/relays/wireguard/v2":
			_, _ = w.Write([]byte(mvRelays4))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	d, _ := testDaemon(t, "[daemon]\nsocket = \"/nonexistent/s.sock\"\ndefault_route = \"direct\"\n[dns]\ndisabled = true\n")
	d.mv.client.Base = srv.URL
	if err := d.reload("shunt"); err != nil {
		t.Fatal(err)
	}
	if err := d.MullvadChain(api.MullvadChain{Name: "ch", Hops: 3}); err == nil {
		t.Fatal("chain without login accepted")
	}
	_ = d.MullvadLogin("a", "1111222233334444")
	_ = d.MullvadLogin("b", "5555666677778888")
	if err := d.MullvadChain(api.MullvadChain{Name: "Bad Name", Hops: 3}); err == nil {
		t.Fatal("bad name accepted")
	}
	if err := d.MullvadChain(api.MullvadChain{Name: "ch", Hops: 3, Entry: "de", Exit: "nl"}); err != nil {
		t.Fatal(err)
	}
	st, _ := d.MullvadStatus()
	if len(st.Exits) != 3 {
		t.Fatalf("%+v", st.Exits)
	}
	by := map[string]api.MullvadExit{}
	for _, e := range st.Exits {
		by[e.Tunnel] = e
	}
	if by["ch1"].Country != "Germany" || by["ch3"].Country != "Netherlands" || by["ch2"].Country == "" {
		t.Fatalf("countries: %+v", by)
	}
	if by["ch1"].Account != "a" || by["ch2"].Account != "b" || by["ch3"].Account != "a" {
		t.Fatalf("accounts in turn: %+v", by)
	}
	d.mu.Lock()
	v2, v3, v1 := d.cfg.Tunnels["ch2"].Via, d.cfg.Tunnels["ch3"].Via, d.cfg.Tunnels["ch1"].Via
	d.mu.Unlock()
	if v1 != "" || v2 != "tunnel:ch1" || v3 != "tunnel:ch2" {
		t.Fatalf("chain via: %q %q %q", v1, v2, v3)
	}
	// same name again: stopped before anything changes
	if err := d.MullvadChain(api.MullvadChain{Name: "ch", Hops: 2}); err == nil {
		t.Fatal("name clash accepted")
	}
	if st, _ = d.MullvadStatus(); len(st.Exits) != 3 {
		t.Fatalf("clash changed the chain: %+v", st.Exits)
	}
	// 4 countries: a 4-hop chain with entry through the old exit
	if err := d.MullvadChain(api.MullvadChain{Name: "lo", Hops: 4, Via: "tunnel:ch3"}); err != nil {
		t.Fatal(err)
	}
	if d.hopDepth("tunnel:lo4") != 7 {
		t.Fatalf("depth %d", d.hopDepth("tunnel:lo4"))
	}
}
