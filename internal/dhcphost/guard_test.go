package dhcphost

import (
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
)

func TestSendsHostname(t *testing.T) {
	for _, c := range []struct {
		name string
		ip   map[string]any
		want bool
	}{
		{"default (left out)", map[string]any{}, true},
		{"bool false", map[string]any{"dhcp-send-hostname": false}, false},
		{"bool true", map[string]any{"dhcp-send-hostname": true}, true},
		{"v2 0", map[string]any{"dhcp-send-hostname-v2": int32(0)}, false},
		{"v2 1", map[string]any{"dhcp-send-hostname-v2": int32(1)}, true},
		{"v2 -1 (global default, not applied by NM 1.52)", map[string]any{"dhcp-send-hostname-v2": int32(-1)}, true},
		{"v2 -1 but bool false", map[string]any{"dhcp-send-hostname-v2": int32(-1), "dhcp-send-hostname": false}, false},
	} {
		if got := sendsHostname(c.ip); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestGuardNeeded(t *testing.T) {
	cfg := func(s string) *config.Config {
		c, err := config.Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	none := cfg("[daemon]\ndhcp_hostname = \"none\"\n[[network]]\nname = \"home\"\nssid = [\"HomeNet\"]\ndefault_route = \"direct\"\ndhcp_hostname = \"send\"\n[[network]]\nname = \"office\"\ngateway_mac = [\"aa:bb:cc:dd:ee:ff\"]\ndefault_route = \"direct\"\ndhcp_hostname = \"send\"\n")
	send := cfg("[daemon]\ndhcp_hostname = \"send\"\n")
	off := cfg("[daemon]\ndhcp_hostname = \"\"\n") // explicit "": leave the profiles alone
	missing := cfg("[daemon]\n")                   // key missing: disguise on (none)
	for _, c := range []struct {
		name string
		pol  Policy
		a    Applied
		want bool
	}{
		{"new cable profile sends, policy none", Policy{Config: none}, Applied{Send4: true, Send6: true}, true},
		{"only DHCPv6 sends", Policy{Config: none}, Applied{Send6: true}, true},
		{"already off", Policy{Config: none}, Applied{}, false},
		{"Wi-Fi network by name may send", Policy{Config: none}, Applied{Wifi: true, SSID: "HomeNet", Send4: true}, false},
		{"other Wi-Fi", Policy{Config: none}, Applied{Wifi: true, SSID: "Cafe", Send4: true}, true},
		// a network known only by its gateway is not recognised while it
		// connects; the network before (Current) must not decide for it
		{"current network may send, new one not recognised", Policy{Config: none, Current: "office"}, Applied{Send4: true}, true},
		{"policy send", Policy{Config: send}, Applied{Send4: true}, false},
		{"explicit empty: leave alone", Policy{Config: off}, Applied{Send4: true}, false},
		{"key missing: default none", Policy{Config: missing}, Applied{Send4: true}, true},
		{"no config", Policy{}, Applied{Send4: true}, false},
	} {
		if got := c.pol.GuardNeeded(c.a); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
	for st, want := range map[uint32]bool{30: false, 40: true, 50: true, 60: true, 70: false, 100: false} {
		if guardState(st) != want {
			t.Errorf("state %d: got %v", st, !want)
		}
	}
}
