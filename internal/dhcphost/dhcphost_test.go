package dhcphost

import (
	"strings"
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

func TestMAC(t *testing.T) {
	c, err := config.Parse(`
[daemon]
mac = "random"
[[network]]
name = "home"
ssid = ["Home"]
default_route = "direct"
mac = "permanent"
[[network]]
name = "office"
gateway_mac = ["11:22:33:44:55:66"]
default_route = "direct"
mac = "stable"
`)
	if err != nil {
		t.Fatal(err)
	}
	pol := Policy{Config: c}
	tidy := Profile{MAC: "random", DUID: "ll", ClientID: "mac", AddrGen: "stable-privacy", Privacy: "2"}
	for _, tc := range []struct {
		name      string
		p         Profile
		current   string
		now, next string
	}{
		{"unknown wifi gets everything", Profile{Wifi: true, SSID: "Cafe", AddrGen: "default", Privacy: "-1"}, "",
			"ipv6.dhcp-duid ll ipv4.dhcp-client-id mac ipv6.addr-gen-mode stable-privacy ipv6.ip6-privacy 2", "802-11-wireless.cloned-mac-address random"},
		{"already set", func() Profile { p := tidy; p.Wifi, p.SSID = true, "Cafe"; return p }(), "", "", ""},
		{"cable too", Profile{Device: "eth0", MAC: "", DUID: "ll", ClientID: "mac", AddrGen: "stable-privacy", Privacy: "2"}, "",
			"", "802-3-ethernet.cloned-mac-address random"},
		{"home wifi by name: real MAC, NM's own IDs", Profile{Wifi: true, SSID: "Home", MAC: "random", DUID: "ll", ClientID: "mac", AddrGen: "stable-privacy"}, "",
			"ipv6.dhcp-duid stable-uuid", "802-11-wireless.cloned-mac-address permanent"},
		{"office once recognised", func() Profile { p := tidy; p.Device = "eth0"; return p }(), "office",
			"ipv6.dhcp-duid stable-ll", "802-3-ethernet.cloned-mac-address stable"},
	} {
		pol.Current = tc.current
		now, next := pol.Changes(tc.p)
		if got := strings.Join(now, " "); got != tc.now {
			t.Errorf("%s: now %q, want %q", tc.name, got, tc.now)
		}
		if got := strings.Join(next, " "); got != tc.next {
			t.Errorf("%s: next %q, want %q", tc.name, got, tc.next)
		}
	}

	// the host name alone still works and leaves the MAC alone
	c.Daemon.MAC, c.Daemon.DHCPHostname = "", config.HostnameNone
	if now, next := pol.Changes(Profile{Wifi: true, SSID: "Cafe", Send4: "yes", Send6: "yes"}); strings.Join(now, " ") != "ipv4.dhcp-send-hostname no ipv6.dhcp-send-hostname no" || next != nil {
		t.Errorf("host name only: %q %q", now, next)
	}
	if _, err := config.Parse("[daemon]\nmac = \"spoof\"\n"); err == nil {
		t.Error("mac = spoof accepted")
	}
}

func TestDefaults(t *testing.T) {
	c, _ := config.Parse("[daemon]\nmac = \"stable\"\ndhcp_hostname = \"none\"\n")
	d := Defaults(c)
	for _, want := range []string{"[connection-shunt-privacy]", "wifi.cloned-mac-address=stable", "ethernet.cloned-mac-address=stable", "ipv6.dhcp-duid=stable-ll", "ipv4.dhcp-client-id=mac", "ipv6.addr-gen-mode=stable-privacy", "ipv6.dhcp-send-hostname=false"} {
		if !strings.Contains(d, want+"\n") && want != "[connection-shunt-privacy]" || !strings.Contains(d, want) {
			t.Errorf("defaults lack %q:\n%s", want, d)
		}
	}
	c.Daemon.MAC, c.Daemon.DHCPHostname = config.MACPermanent, ""
	if d := Defaults(c); d != "" {
		t.Errorf("permanent/off wrote defaults:\n%s", d)
	}
}
