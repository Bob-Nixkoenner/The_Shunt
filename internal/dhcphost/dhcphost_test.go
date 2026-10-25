package dhcphost

import (
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
)

func TestPolicy(t *testing.T) {
	c, err := config.Parse(`
[daemon]
dhcp_hostname = "none"
[[network]]
name = "home"
ssid = ["Home"]
default_route = "direct"
dhcp_hostname = "send"
[[network]]
name = "home-cable"
gateway_mac = ["aa:bb:cc:dd:ee:ff"]
default_route = "direct"
dhcp_hostname = "send"
[[network]]
name = "fake-proof"
ssid = ["Office"]
gateway_mac = ["11:22:33:44:55:66"]
default_route = "direct"
dhcp_hostname = "send"
`)
	if err != nil {
		t.Fatal(err)
	}
	pol := Policy{Config: c}
	for _, tc := range []struct {
		name    string
		p       Profile
		current string
		want    string
	}{
		{"unknown wifi sends by default", Profile{Wifi: true, SSID: "Cafe", Send4: "yes", Send6: "yes"}, "", "no"},
		{"1.54 default (-1) sends", Profile{Wifi: true, SSID: "Cafe", Send4: "-1", Send6: "-1"}, "", "no"},
		{"already off", Profile{Wifi: true, SSID: "Cafe", Send4: "no", Send6: "0"}, "", ""},
		{"home wifi by name", Profile{Wifi: true, SSID: "Home", Send4: "no", Send6: "no"}, "", "yes"},
		{"ssid with gateway_mac waits for the network", Profile{Wifi: true, SSID: "Office", Send4: "yes", Send6: "yes"}, "", "no"},
		{"... and sends once recognised", Profile{Wifi: true, SSID: "Office", Device: "wlan0", Send4: "no", Send6: "no"}, "fake-proof", "yes"},
		{"cable elsewhere", Profile{UUID: "u", Device: "eth0", Send4: "yes", Send6: "yes"}, "", "no"},
		{"cable at home", Profile{UUID: "u", Device: "eth0", Send4: "no", Send6: "no"}, "home-cable", "yes"},
		{"cable not in use goes back", Profile{UUID: "u", Send4: "yes", Send6: "yes"}, "home-cable", "no"},
	} {
		pol.Current = tc.current
		if got := pol.Change(tc.p); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}

	c.Daemon.DHCPHostname = ""
	if got := pol.Change(Profile{Wifi: true, SSID: "Cafe", Send4: "yes"}); got != "" {
		t.Errorf("switched off: got %q", got)
	}
}

func TestBadMode(t *testing.T) {
	if _, err := config.Parse("[daemon]\ndhcp_hostname = \"random\"\n"); err == nil {
		t.Error("random accepted")
	}
}
