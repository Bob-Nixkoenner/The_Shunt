package daemon

import (
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
	if err := d.MullvadLogin("12345"); err == nil {
		t.Fatal("short account accepted")
	}
	if err := d.MullvadLogin("1234 5678 9012 3456"); err != nil {
		t.Fatal(err)
	}
	if err := d.MullvadLogin("1234567890123456"); err == nil {
		t.Fatal("second login accepted")
	}
	if fi, err := os.Stat(d.mullvadPath()); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatal("store must be mode 600", err)
	}
	st, _ := d.MullvadStatus()
	if !st.LoggedIn || st.Account != "••••3456" || st.Device != "happy fox" {
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
	if err := d.MullvadLogout(); err != nil {
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
