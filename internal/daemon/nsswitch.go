package daemon

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

const (
	nsswitchPath   = "/etc/nsswitch.conf"
	nsswitchBackup = "/etc/nsswitch.conf.shunt-backup"
)

// StripResolve removes nss-resolve from the hosts line, so glibc resolves
// through /etc/resolv.conf (port 53, which Shunt redirects per route)
// instead of asking systemd-resolved over varlink.
func StripResolve(conf string) (string, bool) {
	lines := strings.Split(conf, "\n")
	changed := false
	for i, l := range lines {
		f := strings.Fields(l)
		if len(f) == 0 || f[0] != "hosts:" {
			continue
		}
		out := []string{f[0]}
		for j := 1; j < len(f); j++ {
			if f[j] == "resolve" {
				changed = true
				// drop its action block too, e.g. [!UNAVAIL=return]
				if j+1 < len(f) && strings.HasPrefix(f[j+1], "[") {
					j++
				}
				continue
			}
			out = append(out, f[j])
		}
		if !contains(out, "dns") {
			out = append(out, "dns")
		}
		lines[i] = strings.Join(out, " ")
	}
	return strings.Join(lines, "\n"), changed
}

func contains(s []string, x string) bool {
	for _, v := range s {
		if v == x {
			return true
		}
	}
	return false
}

// FixNsswitch applies StripResolve to /etc/nsswitch.conf, keeping a backup.
func FixNsswitch() (bool, error) {
	b, err := os.ReadFile(nsswitchPath)
	if err != nil {
		return false, err
	}
	fixed, changed := StripResolve(string(b))
	if !changed {
		return false, nil
	}
	if _, err := os.Stat(nsswitchBackup); errors.Is(err, os.ErrNotExist) {
		if err := os.WriteFile(nsswitchBackup, b, 0o644); err != nil {
			return false, err
		}
	}
	tmp := nsswitchPath + ".shunt-tmp"
	if err := os.WriteFile(tmp, []byte(fixed), 0o644); err != nil {
		return false, err
	}
	return true, os.Rename(tmp, nsswitchPath)
}

// RestoreNsswitch puts the backup made by FixNsswitch back.
func RestoreNsswitch() error {
	b, err := os.ReadFile(nsswitchBackup)
	if err != nil {
		return fmt.Errorf("no backup at %s: %w", nsswitchBackup, err)
	}
	if err := os.WriteFile(nsswitchPath, b, 0o644); err != nil {
		return err
	}
	return os.Remove(nsswitchBackup)
}
