// Package dhcphost sets what NetworkManager shows a network about this
// device, per connection profile: the host name in DHCP (daemon.dhcp_hostname)
// and the MAC address with the IDs derived from it (daemon.mac: DHCPv6 DUID,
// DHCPv4 client ID, IPv6 interface IDs). NetworkManager has no working
// global switch for the host name (1.46 has none, 1.54 ignores it for
// profiles that leave the value unset), and global defaults do not tell
// networks apart, so the profiles themselves are set.
package dhcphost

import (
	"fmt"
	"strings"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
)

// Profile is a Wi-Fi or cable connection profile as NetworkManager has it.
// The string fields hold the values as nmcli -g prints them ("" = unset).
type Profile struct {
	UUID   string
	Wifi   bool   // else cable
	SSID   string // Wi-Fi only
	Device string // in use on this interface right now ("" = not active)
	// Activated: fully up. Connecting: on its way; such a profile is left
	// alone (a change restarts the connection with yet another MAC), the
	// defaults for new profiles cover it and the next pass sets it.
	Activated, Connecting bool
	// Send4/Send6: ipv4/ipv6.dhcp-send-hostname.
	Send4, Send6 string
	MAC          string // 802-11-wireless/802-3-ethernet.cloned-mac-address
	DUID         string // ipv6.dhcp-duid
	ClientID     string // ipv4.dhcp-client-id
	AddrGen      string // ipv6.addr-gen-mode
	Privacy      string // ipv6.ip6-privacy
}

// Policy decides per profile.
type Policy struct {
	Config *config.Config
	// Current: the [[network]] recognised right now ("" = none). It
	// decides for the profiles in use.
	Current string
}

// pick returns the daemon wide value, overridden by a Wi-Fi network matched
// by name alone (no gateway_mac) already before it connects, and by the
// current network for the profile in use. "" = leave the profile alone.
func (pol Policy) pick(p Profile, daemon string, of func(config.Network) string) string {
	if daemon == "" {
		return ""
	}
	mode := daemon
	c := pol.Config
	if p.Wifi && p.SSID != "" {
		for _, n := range c.Networks {
			if len(n.GatewayMAC) == 0 && of(n) != "" && contains(n.SSID, p.SSID) {
				mode = of(n)
				break
			}
		}
	}
	if p.Device != "" && pol.Current != "" {
		for _, n := range c.Networks {
			if n.Name == pol.Current && of(n) != "" {
				mode = of(n)
			}
		}
	}
	return mode
}

// Mode returns the host name mode for p.
func (pol Policy) Mode(p Profile) string {
	return pol.pick(p, pol.Config.Daemon.DHCPHostname, func(n config.Network) string { return n.DHCPHostname })
}

// MACMode returns the MAC mode for p.
func (pol Policy) MACMode(p Profile) string {
	return pol.pick(p, pol.Config.Daemon.MAC, func(n config.Network) string { return n.MAC })
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

// Changes returns the nmcli property/value pairs p needs: now can be
// reapplied to a connection in use, next (the MAC) only takes effect when
// the profile connects again.
func (pol Policy) Changes(p Profile) (now, next []string) {
	set := func(l *[]string, prop, have, want string) {
		if have != want {
			*l = append(*l, prop, want)
		}
	}
	if v := pol.Change(p); v != "" {
		now = append(now, "ipv4.dhcp-send-hostname", v, "ipv6.dhcp-send-hostname", v)
	}
	macProp := "802-3-ethernet.cloned-mac-address"
	if p.Wifi {
		macProp = "802-11-wireless.cloned-mac-address"
	}
	switch pol.MACMode(p) {
	case config.MACRandom, config.MACStable:
		mac, duid := "random", "ll" // DUID-LL from the (new) MAC
		if pol.MACMode(p) == config.MACStable {
			mac, duid = "stable", "stable-ll" // from the profile's stable ID, not the machine ID
		}
		set(&now, "ipv6.dhcp-duid", p.DUID, duid)
		set(&now, "ipv4.dhcp-client-id", p.ClientID, "mac") // follows the cloned MAC
		set(&now, "ipv6.addr-gen-mode", p.AddrGen, "stable-privacy")
		set(&now, "ipv6.ip6-privacy", p.Privacy, "2")
		set(&next, macProp, p.MAC, mac)
	case config.MACPermanent:
		// a trusted network: the real MAC; a DUID of this profile's own
		// (unset would take the runtime default, see Defaults)
		set(&now, "ipv6.dhcp-duid", p.DUID, "stable-uuid")
		set(&now, "ipv4.dhcp-client-id", p.ClientID, "mac")
		set(&next, macProp, p.MAC, "permanent")
	}
	return now, next
}

// Covered tells whether the connection in use already runs with now: each
// of these properties was unset in p and the runtime defaults (Defaults)
// gave it the same value. Then now only goes into the profile; a reapply
// would restart DHCP for nothing (its answers then hit a closed socket and
// the network gets ICMP errors back).
func (pol Policy) Covered(p Profile, now []string) bool {
	d := pol.Config.Daemon
	def := map[string]string{}
	switch d.MAC {
	case config.MACRandom, config.MACStable:
		def["ipv6.dhcp-duid"] = "ll"
		if d.MAC == config.MACStable {
			def["ipv6.dhcp-duid"] = "stable-ll"
		}
		def["ipv4.dhcp-client-id"] = "mac"
		def["ipv6.addr-gen-mode"] = "stable-privacy"
		def["ipv6.ip6-privacy"] = "2"
	}
	if d.DHCPHostname == config.HostnameNone {
		def["ipv4.dhcp-send-hostname"] = "no"
		def["ipv6.dhcp-send-hostname"] = "no"
	}
	had := map[string]string{
		"ipv4.dhcp-send-hostname": p.Send4, "ipv6.dhcp-send-hostname": p.Send6,
		"ipv6.dhcp-duid": p.DUID, "ipv4.dhcp-client-id": p.ClientID,
		"ipv6.addr-gen-mode": p.AddrGen, "ipv6.ip6-privacy": p.Privacy,
	}
	for i := 0; i+1 < len(now); i += 2 {
		v, ok := had[now[i]]
		if !ok || !unsetValue(v) || def[now[i]] != now[i+1] {
			return false
		}
	}
	return len(now) > 0
}

// unsetValue: nmcli's spellings of "not set in the profile" (1.52+:
// -1/default; 1.46 always shows yes/no for dhcp-send-hostname).
func unsetValue(v string) bool { return v == "" || v == "-1" || v == "default" }

// Defaults returns NetworkManager connection defaults for profiles that do
// not set these values: a network joined for the first time connects at
// once, before its new profile can be set. "" = none needed.
func Defaults(c *config.Config) string {
	var b strings.Builder
	switch c.Daemon.MAC {
	case config.MACRandom, config.MACStable:
		mac, duid := "random", "ll"
		if c.Daemon.MAC == config.MACStable {
			mac, duid = "stable", "stable-ll"
		}
		fmt.Fprintf(&b, "wifi.cloned-mac-address=%s\nethernet.cloned-mac-address=%s\nipv6.dhcp-duid=%s\nipv4.dhcp-client-id=mac\nipv6.addr-gen-mode=stable-privacy\nipv6.ip6-privacy=2\n", mac, mac, duid)
	}
	if c.Daemon.DHCPHostname == config.HostnameNone {
		// 0, not false: NetworkManager 1.52+ reads the default as a number
		// (-1/0/1) and ignores "false"; 1.46 reads 0 as no as well
		b.WriteString("ipv4.dhcp-send-hostname=0\nipv6.dhcp-send-hostname=0\n")
	}
	if b.Len() == 0 {
		return ""
	}
	return "# Written by shuntd at start (daemon.mac, daemon.dhcp_hostname): defaults for\n# profiles that do not set these, so a new network is covered from its first\n# connection. Runtime only; shuntd removes it when the settings are off.\n# A section of its own: NetworkManager checks named [connection-…] sections\n# before the plain [connection] (e.g. 90-shunt-privacy.conf in /etc).\n[connection-shunt-privacy]\n" + b.String()
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
