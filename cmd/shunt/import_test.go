package main

import "testing"

func TestTunnelName(t *testing.T) {
	for in, want := range map[string]string{
		"/etc/wireguard/Laptop.conf": "laptop",
		"Mullvad-DE_fra 001.conf":    "mullvad-de",
		"de-fra-wg-001.conf":         "de-fra-wg",
		"-x.ovpn":                    "x",
		"ÄÖÜ.conf":                   "tunnel",
		"ch.protonvpn.udp.ovpn":      "ch-protonv",
	} {
		if got := tunnelName(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}
