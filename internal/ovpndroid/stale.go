package ovpndroid

import (
	"path/filepath"

	"github.com/Bob-Nixkoenner/the_shunt/internal/secfile"
)

// ConfName is the config file in a tunnel's work folder; it exists only
// while openvpn starts.
const ConfName = "tunnel.ovpn"

// CleanStale wipes config files left in base/<tunnel>/ (base: the folder of
// the OpenVPN work folders) by a run that crashed or was killed before
// openvpn read them. Call it only while no openvpn of this app starts.
func CleanStale(base string) int {
	if base == "" {
		return 0
	}
	return secfile.WipeGlob(filepath.Join(base, "*", ConfName))
}
