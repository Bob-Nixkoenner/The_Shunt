package mullvad

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/wgconf"
)

const relayJSON = `{"locations":{"de-fra":{"country":"Germany","city":"Frankfurt"},"se-got":{"country":"Sweden","city":"Gothenburg"}},
"wireguard":{"ipv4_gateway":"10.64.0.1","relays":[
{"hostname":"de-fra-wg-001","location":"de-fra","active":true,"ipv4_addr_in":"198.51.100.1","public_key":"ofyfRvMPB0PPIGGItNL+5tNdvTKXuWye5CfjPgPNvQ8=","weight":100,"include_in_country":true},
{"hostname":"de-fra-wg-002","location":"de-fra","active":false,"ipv4_addr_in":"198.51.100.2","public_key":"ofyfRvMPB0PPIGGItNL+5tNdvTKXuWye5CfjPgPNvQ8=","weight":100,"include_in_country":true},
{"hostname":"se-got-wg-001","location":"se-got","active":true,"ipv4_addr_in":"198.51.100.3","public_key":"ofyfRvMPB0PPIGGItNL+5tNdvTKXuWye5CfjPgPNvQ8=","weight":50,"include_in_country":true}]}}`

func list(t *testing.T) *RelayList {
	var l RelayList
	if err := json.Unmarshal([]byte(relayJSON), &l); err != nil {
		t.Fatal(err)
	}
	return &l
}

func TestNormalizeAccount(t *testing.T) {
	if a, err := NormalizeAccount("1234 5678-9012 3456"); err != nil || a != "1234567890123456" {
		t.Fatal(a, err)
	}
	for _, bad := range []string{"", "123", "abcdabcdabcdabcd", "12345678901234567"} {
		if _, err := NormalizeAccount(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestCountriesPick(t *testing.T) {
	l := list(t)
	cs := l.Countries()
	if len(cs) != 2 || cs[0].Code != "de" || cs[0].Servers != 1 || cs[0].Cities[0].Code != "de-fra" {
		t.Fatalf("%+v", cs)
	}
	r, err := l.Pick(Choice{Country: "de"})
	if err != nil || r.Hostname != "de-fra-wg-001" { // -002 is inactive
		t.Fatal(r, err)
	}
	if r, err = l.Pick(Choice{City: "se-got"}); err != nil || r.Hostname != "se-got-wg-001" {
		t.Fatal(r, err)
	}
	if r, err = l.Pick(Choice{Hostname: "se-got-wg-001"}); err != nil || r.Location != "se-got" {
		t.Fatal(r, err)
	}
	if _, err = l.Pick(Choice{Hostname: "de-fra-wg-002"}); err == nil {
		t.Fatal("inactive server picked")
	}
	if _, err = l.Pick(Choice{Country: "xx"}); err == nil {
		t.Fatal("no match must fail")
	}
	if r, err = l.Pick(Choice{}); err != nil || !r.Active {
		t.Fatal(r, err)
	}
}

func TestKeyAndConfParse(t *testing.T) {
	priv, pub, err := NewKey()
	if err != nil || priv == pub || len(priv) != 44 || len(pub) != 44 {
		t.Fatal(priv, pub, err)
	}
	l := list(t)
	r, _ := l.Pick(Choice{Hostname: "de-fra-wg-001"})
	conf, err := Conf(priv, &Device{IPv4: "10.70.1.2/32", IPv6: "fc00:bbbb:bbbb:bb01::1:2/128"}, r, l.WireGuard.Gateway, 0)
	if err != nil {
		t.Fatal(err)
	}
	wc, err := wgconf.Parse(strings.NewReader(conf))
	if err != nil {
		t.Fatalf("%v\n%s", err, conf)
	}
	if len(wc.Peers) != 1 || wc.Peers[0].Endpoint != "198.51.100.1:51820" || !wc.HasIPv4() || !wc.HasIPv6() || len(wc.DNS) != 1 {
		t.Fatalf("%+v", wc)
	}
	c2, _ := Conf(priv, &Device{IPv4: "10.70.1.2/32"}, r, "", HopMTU(2))
	if !strings.Contains(c2, "MTU = 1260") && !strings.Contains(c2, "MTU = 1280") {
		t.Fatalf("hop MTU missing:\n%s", c2)
	}
	if HopMTU(0) != 0 || HopMTU(1) != 1340 || HopMTU(9) != 1280 {
		t.Fatal(HopMTU(1), HopMTU(9))
	}
	if _, err := Conf(priv, &Device{IPv4: "10.0.0.1/32\n[Peer]"}, r, "", 0); err == nil {
		t.Fatal("injection accepted")
	}
}

func TestAPI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "POST /auth/v1/token":
			var b map[string]string
			_ = json.NewDecoder(r.Body).Decode(&b)
			if b["account_number"] != "1234567890123456" {
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`{"code":"INVALID_ACCOUNT","error":"Bad account number"}`))
				return
			}
			_, _ = w.Write([]byte(`{"access_token":"tok"}`))
		case "POST /accounts/v1/devices":
			if r.Header.Get("Authorization") != "Bearer tok" {
				w.WriteHeader(401)
				return
			}
			_, _ = w.Write([]byte(`{"id":"abc-1","name":"happy fox","ipv4_address":"10.70.1.2/32","ipv6_address":"fc00::2/128"}`))
		case "DELETE /accounts/v1/devices/abc-1":
			w.WriteHeader(204)
		case "GET /public/relays/wireguard/v2":
			_, _ = w.Write([]byte(relayJSON))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	c := &Client{Base: srv.URL}
	ctx := context.Background()
	if _, err := c.Token(ctx, "0000000000000000"); err == nil || !strings.Contains(err.Error(), "not valid") {
		t.Fatal(err)
	}
	tok, err := c.Token(ctx, "1234567890123456")
	if err != nil {
		t.Fatal(err)
	}
	d, err := c.AddDevice(ctx, tok, "pub")
	if err != nil || d.ID != "abc-1" {
		t.Fatal(d, err)
	}
	if err := c.DeleteDevice(ctx, tok, d.ID); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteDevice(ctx, tok, "../x"); err == nil {
		t.Fatal("bad id accepted")
	}
	if l, err := c.Relays(ctx); err != nil || len(l.WireGuard.Relays) != 3 {
		t.Fatal(l, err)
	}
}

func TestPickChain(t *testing.T) {
	var l RelayList
	l.Locations = map[string]Location{}
	for i, cc := range []string{"de", "se", "ch", "nl", "us"} {
		loc := cc + "-xx"
		l.Locations[loc] = Location{Country: cc, City: "x"}
		for j := 0; j < 3; j++ {
			prov := []string{"A", "B", "C"}[(i+j)%3]
			l.WireGuard.Relays = append(l.WireGuard.Relays, Relay{Hostname: fmt.Sprintf("%s-wg-%03d", cc, j), Location: loc,
				Active: true, IncludeInCountry: true, Provider: prov, IPv4: "198.51.100.1", PubKey: "k"})
		}
	}
	l.WireGuard.Relays[0].Active = false
	for n := 0; n < 200; n++ {
		c, err := l.PickChain(3, "de", "us")
		if err != nil || len(c) != 3 {
			t.Fatal(c, err)
		}
		cc := map[string]bool{}
		prov := map[string]bool{}
		for _, r := range c {
			cc[countryCode(r.Location)] = true
			prov[r.Provider] = true
			if !r.Active {
				t.Fatal("inactive relay")
			}
		}
		if len(cc) != 3 || countryCode(c[0].Location) != "de" || countryCode(c[2].Location) != "us" {
			t.Fatalf("countries wrong: %v", cc)
		}
		if len(prov) != 3 {
			t.Fatalf("providers not spread: %v", prov)
		}
	}
	if _, err := l.PickChain(6, "", ""); err == nil {
		t.Fatal("6 hops accepted")
	}
	if _, err := l.PickChain(3, "de", "de"); err == nil {
		t.Fatal("same entry and exit accepted")
	}
	if _, err := l.PickChain(3, "xx", ""); err == nil {
		t.Fatal("unknown country accepted")
	}
	if _, err := l.PickChain(4, "", ""); err != nil {
		t.Fatal(err)
	}
}
