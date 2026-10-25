// Package dhcphost keeps NetworkManager from sending the host name in DHCP,
// per connection profile. NetworkManager has no working global switch for
// it (1.46 has none, 1.54 ignores it for profiles that leave the value
// unset), so the profiles themselves are set.
package dhcphost

import (
	"strings"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
)

// Profile is a Wi-Fi or cable connection profile as NetworkManager has it.
type Profile struct {
	UUID   string
	Wifi   bool   // else cable
	SSID   string // Wi-Fi only
	Device string // in use on this interface right now ("" = not active)
	// Send4/Send6: the profile's dhcp-send-hostname as nmcli prints it.
	Send4, Send6 string
}

// Policy decides per profile.
type Policy struct {
	Config *config.Config
	// Current: the [[network]] recognised right now ("" = none). It
	// decides for the profiles in use.
	Current string
}

// Mode returns the mode for p: daemon.dhcp_hostname, a Wi-Fi network
// matched by name alone (no gateway_mac) already before it connects, the
// current network for the profile in use. "" = leave the profile alone.
func (pol Policy) Mode(p Profile) string {
	c := pol.Config
	mode := c.Daemon.DHCPHostname
	if mode == "" {
		return ""
	}
	if p.Wifi && p.SSID != "" {
		for _, n := range c.Networks {
			if len(n.GatewayMAC) == 0 && n.DHCPHostname != "" && contains(n.SSID, p.SSID) {
				mode = n.DHCPHostname
				break
			}
		}
	}
	if p.Device != "" && pol.Current != "" {
		for _, n := range c.Networks {
			if n.Name == pol.Current && n.DHCPHostname != "" {
				mode = n.DHCPHostname
			}
		}
	}
	return mode
}

// Change returns the value to set for both ipv4 and ipv6
// dhcp-send-hostname ("yes" or "no"), or "" when p is fine as it is.
func (pol Policy) Change(p Profile) string {
	want := ""
	switch pol.Mode(p) {
	case config.HostnameNone:
		want = "no"
	case config.HostnameSend:
		want = "yes"
	default:
		return ""
	}
	if normSend(p.Send4) == want && normSend(p.Send6) == want {
		return ""
	}
	return want
}

// normSend maps nmcli's spellings (1.46: yes/no; 1.52+: -1/0/1, "default")
// to yes/no; the default sends (NetworkManager's fallback).
func normSend(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "no", "0", "false":
		return "no"
	}
	return "yes"
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}
