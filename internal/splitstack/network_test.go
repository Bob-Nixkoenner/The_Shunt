package splitstack

import "testing"

// A profile with gateway_mac matches only with that router (any case); one
// without it ignores the MAC, as before (Android never knows it).
func TestMatchNetworkGatewayMAC(t *testing.T) {
	ns := []networkConf{
		{Name: "home", GatewayMAC: []string{"AA:BB:CC:00:11:22"}},
		{Name: "cafe", SSID: []string{"Cafe"}},
		{Name: "cable", Link: "ethernet"},
	}
	for _, c := range []struct{ link, ssid, mac, want string }{
		{"ethernet", "", "aa:bb:cc:00:11:22", "home"},
		{"wifi", "Cafe", "aa:bb:cc:00:11:22", "home"},
		{"ethernet", "", "02:00:00:00:00:01", "cable"},
		{"ethernet", "", "", "cable"},
		{"wifi", "Cafe", "", "cafe"},
		{"wifi", "Other", "02:00:00:00:00:01", ""},
	} {
		got := ""
		if n := matchNetwork(ns, c.link, c.ssid, c.mac); n != nil {
			got = n.Name
		}
		if got != c.want {
			t.Errorf("%s %q %q: got %q, want %q", c.link, c.ssid, c.mac, got, c.want)
		}
	}
}
