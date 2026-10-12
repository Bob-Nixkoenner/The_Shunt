// Package netdetect tells which network the machine is on: the Wi-Fi name
// (SSID) and the MAC address of the default gateway. Network profiles
// ([[network]] in the config) match on these.
//
// An SSID is trivial to fake (anyone can call a hotspot "FritzBox"); the
// gateway MAC is harder to guess. Profiles that relax protection should
// match on both.
package netdetect

// Info describes the current uplink. Empty fields are unknown.
type Info struct {
	Iface      string `json:"iface,omitempty"`
	SSID       string `json:"ssid,omitempty"`
	GatewayIP  string `json:"gateway_ip,omitempty"`
	GatewayMAC string `json:"gateway_mac,omitempty"`
}

// Key identifies the network for change detection.
func (i Info) Key() string { return i.Iface + "|" + i.SSID + "|" + i.GatewayMAC }
