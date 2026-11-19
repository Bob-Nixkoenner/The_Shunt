package mobile

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/wgconf"
)

const mvRelays = `{"locations":{"de-fra":{"country":"Germany","city":"Frankfurt"},"se-got":{"country":"Sweden","city":"Gothenburg"},"ch-zrh":{"country":"Switzerland","city":"Zurich"}},
"wireguard":{"ipv4_gateway":"10.64.0.1","relays":[
{"hostname":"de-fra-wg-001","location":"de-fra","active":true,"provider":"A","ipv4_addr_in":"198.51.100.1","public_key":"ofyfRvMPB0PPIGGItNL+5tNdvTKXuWye5CfjPgPNvQ8=","weight":100,"include_in_country":true},
{"hostname":"se-got-wg-001","location":"se-got","active":true,"provider":"B","ipv4_addr_in":"198.51.100.3","public_key":"ofyfRvMPB0PPIGGItNL+5tNdvTKXuWye5CfjPgPNvQ8=","weight":50,"include_in_country":true},
{"hostname":"ch-zrh-wg-001","location":"ch-zrh","active":true,"provider":"C","ipv4_addr_in":"198.51.100.4","public_key":"ofyfRvMPB0PPIGGItNL+5tNdvTKXuWye5CfjPgPNvQ8=","weight":50,"include_in_country":true}]}}`

func TestMullvadBridge(t *testing.T) {
	if _, err := MullvadNormalizeAccount("12"); err == nil {
		t.Fatal("short account accepted")
	}
	kj, err := MullvadNewKey()
	var k map[string]string
	if err != nil || json.Unmarshal([]byte(kj), &k) != nil || len(k["private"]) != 44 || k["private"] == k["public"] {
		t.Fatal(kj, err)
	}
	cs, err := MullvadCountries(mvRelays)
	if err != nil || !strings.Contains(cs, `"code":"de"`) || !strings.Contains(cs, `"hosts":["de-fra-wg-001"]`) {
		t.Fatal(cs, err)
	}
	login := `{"private_key":"` + k["private"] + `","ipv4":"10.70.1.2/32","ipv6":"fc00::2/128"}`
	out, err := MullvadConf(mvRelays, login, `{"country":"de"}`, 0)
	var r map[string]string
	if err != nil || json.Unmarshal([]byte(out), &r) != nil || r["hostname"] != "de-fra-wg-001" || r["city"] != "Frankfurt" {
		t.Fatal(out, err)
	}
	if _, err := wgconf.Parse(strings.NewReader(r["conf"])); err != nil {
		t.Fatal(err, r["conf"])
	}
	out2, _ := MullvadConf(mvRelays, login, `{"hostname":"se-got-wg-001"}`, 2)
	if !strings.Contains(out2, `MTU = 1280`) {
		t.Fatal(out2)
	}
	if _, err := MullvadConf(mvRelays, login, `{"country":"xx"}`, 0); err == nil {
		t.Fatal("unknown country accepted")
	}
	if _, err := MullvadConf("{}", login, `{}`, 0); err == nil {
		t.Fatal("empty list accepted")
	}
	ch, err := MullvadChainPick(mvRelays, 3, "de", "ch")
	var hops []map[string]string
	if err != nil || json.Unmarshal([]byte(ch), &hops) != nil || len(hops) != 3 || hops[0]["hostname"] != "de-fra-wg-001" || hops[2]["hostname"] != "ch-zrh-wg-001" {
		t.Fatal(ch, err)
	}
	if _, err := MullvadChainPick(mvRelays, 4, "", ""); err == nil {
		t.Fatal("4 hops from 3 countries accepted")
	}
}
