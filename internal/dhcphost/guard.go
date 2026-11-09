package dhcphost

import "github.com/Bob-Nixkoenner/the_shunt/internal/config"

// Applied is what a connection (applied to a device, or a stored profile)
// says about the host name, read from NetworkManager's settings over D-Bus.
type Applied struct {
	UUID string
	Wifi bool   // else cable
	SSID string // Wi-Fi only
	// Send4/Send6: will DHCPv4/DHCPv6 carry the host name?
	Send4, Send6 bool
}

// sendsHostname reads one IP section (ipv4 or ipv6) of NetworkManager's
// settings. GetSettings leaves out values at their default, and the default
// sends: "dhcp-send-hostname" (bool) false, or "dhcp-send-hostname-v2"
// (int32, NM 1.52+) 0, turn it off; v2 -1 means "global default", which
// NetworkManager 1.52 does not apply (it sends, seen in the lab).
func sendsHostname(ip map[string]any) bool {
	switch n := ip["dhcp-send-hostname-v2"].(type) {
	case int32:
		if n == 0 || n == 1 {
			return n == 1
		}
	case int64:
		if n == 0 || n == 1 {
			return n == 1
		}
	}
	if v, ok := ip["dhcp-send-hostname"].(bool); ok {
		return v
	}
	return true
}

// GuardNeeded tells whether a connection that is starting must be stopped
// before its DHCP: it would send the host name although the policy wants
// none. The network is not recognised yet while it connects, so only the
// daemon wide value and a [[network]] matched by Wi-Fi name decide (not
// pol.Current, which still names the network before).
func (pol Policy) GuardNeeded(a Applied) bool {
	if pol.Config == nil {
		return false
	}
	p := Profile{UUID: a.UUID, Wifi: a.Wifi, SSID: a.SSID}
	if pol.Mode(p) != config.HostnameNone {
		return false
	}
	return a.Send4 || a.Send6
}

// guardState: NetworkManager device states in which a connection is on its
// way but has not started DHCP yet (PREPARE, CONFIG, NEED_AUTH). DHCP starts
// with IP_CONFIG (70).
func guardState(st uint32) bool { return st == 40 || st == 50 || st == 60 }
