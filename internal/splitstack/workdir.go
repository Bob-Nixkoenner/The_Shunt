package splitstack

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/Bob-Nixkoenner/the_shunt/internal/ovpndroid"
	"github.com/Bob-Nixkoenner/the_shunt/internal/secfile"
)

// CleanWorkDir tidies the work_dir of a config (Android: the app's files
// folder) while no engine runs: it wipes OpenVPN config files and torrcs a
// crashed or killed run left behind (they hold keys and bridge lines and
// normally live only while openvpn/tor start) and removes the openvpn/ and
// tor/ folders of tunnels that are no longer in the config (Tor's state there
// names the bridges used). Tailscale folders and the GeoIP files stay. It
// returns how many files and folders went. Call it before New and after
// Stop, never while an engine of this app runs.
func CleanWorkDir(configJSON string) int {
	c, err := parseConfig(configJSON)
	if err != nil || c.WorkDir == "" {
		return 0
	}
	keep := map[string]bool{}
	for _, t := range c.Tunnels {
		first, _, _ := strings.Cut(filepath.ToSlash(t.Name), "/")
		keep[first] = true
	}
	n := ovpndroid.CleanStale(filepath.Join(c.WorkDir, "openvpn"))
	n += secfile.WipeGlob(filepath.Join(c.WorkDir, "tor", "*", "torrc"))
	for _, kind := range []string{"openvpn", "tor"} {
		base := filepath.Join(c.WorkDir, kind)
		ents, _ := os.ReadDir(base)
		for _, e := range ents {
			if e.IsDir() && !keep[e.Name()] && os.RemoveAll(filepath.Join(base, e.Name())) == nil {
				n++
			}
		}
	}
	return n
}
