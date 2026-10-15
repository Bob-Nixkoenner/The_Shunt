package winsplit

import (
	"fmt"
	"os/exec"
	"strings"
)

// The kill switch uses Windows Firewall: outgoing traffic is blocked by
// default, and only these rules let traffic out:
//   - the Shunt service itself (its tunnels and direct sockets)
//   - anything that comes from the Shunt adapter's address, i.e. apps
//     whose packets entered the split
//   - the local network, multicast and DHCP (loopback is never filtered)
//
// An app that tries to bypass the adapter (own sockets on the real
// interface, a route trick) has another source address and is dropped.
// After a crash the rules stay, so nothing leaks until the service is back.

const ksPrefix = "Shunt KS "

var ksRules = []string{"service", "tunnel v4", "tunnel v6", "lan", "dhcp", "dhcp6"}

func fw(args ...string) error {
	if out, err := exec.Command("netsh", append([]string{"advfirewall"}, args...)...).CombinedOutput(); err != nil {
		return fmt.Errorf("netsh advfirewall %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func addRule(name string, params ...string) error {
	return fw(append([]string{"firewall", "add", "rule", "name=" + ksPrefix + name, "dir=out", "action=allow", "enable=yes", "profile=any"}, params...)...)
}

// EnableKillSwitch installs the rules and then the block-by-default policy
// (rules first: a failure half way must not lock the machine out).
func EnableKillSwitch(exe string) error {
	for _, n := range ksRules {
		_ = fw("firewall", "delete", "rule", "name="+ksPrefix+n) // from an earlier run
	}
	rules := []struct {
		name   string
		params []string
	}{
		{"service", []string{"program=" + exe}},
		{"tunnel v4", []string{"localip=10.111.0.2"}},
		{"tunnel v6", []string{"localip=fd11:5ee:bad:c0de::2"}},
		{"lan", []string{"remoteip=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,224.0.0.0/4,255.255.255.255,fe80::/10,fc00::/7,ff00::/8"}},
		{"dhcp", []string{"protocol=udp", "localport=68", "remoteport=67"}},
		{"dhcp6", []string{"protocol=udp", "localport=546", "remoteport=547"}},
	}
	for _, r := range rules {
		if err := addRule(r.name, r.params...); err != nil {
			DisableKillSwitch()
			return err
		}
	}
	if err := fw("set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound"); err != nil {
		DisableKillSwitch()
		return err
	}
	return nil
}

// DisableKillSwitch restores Windows' default (outgoing allowed) and removes
// the rules. Safe to call when nothing is installed.
func DisableKillSwitch() {
	_ = fw("set", "allprofiles", "firewallpolicy", "blockinbound,allowoutbound")
	for _, n := range ksRules {
		_ = fw("firewall", "delete", "rule", "name="+ksPrefix+n)
	}
}
