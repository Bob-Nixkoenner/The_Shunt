package winsplit

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strings"

	"github.com/Bob-Nixkoenner/the_shunt/internal/winsplit/wfp"
)

// The kill switch lives in the Windows Filtering Platform (package wfp): a
// sublayer above Windows Firewall that blocks everything except the service
// itself, the Shunt adapter, loopback, DHCP/NDP and the local network (not
// its DNS). Windows Firewall rules could not do this: Windows' own allow
// rules (core networking DNS, push notifications, store apps) punched
// through a "block outbound" policy. The filters are persistent: they stay
// while the service is stopped, after a crash and across reboots, until
// DisableKillSwitch.
//
// Before 0.7.1 the kill switch was a set of Windows Firewall rules plus a
// "block outbound" policy; legacyCleanup removes them.

const ksPrefix = "Shunt KS "

var ksRules = []string{"service", "tunnel v4", "tunnel v6", "lan", "dhcp", "dhcp6"} // legacy rule names

func fw(args ...string) error {
	if out, err := exec.Command("netsh", append([]string{"advfirewall"}, args...)...).CombinedOutput(); err != nil {
		return fmt.Errorf("netsh advfirewall %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// EnableKillSwitch installs the kill switch for the adapter with LUID luid
// (replacing an earlier one). dns is the only DNS server apps may ask.
func EnableKillSwitch(luid uint64, dns netip.Addr) error {
	legacyCleanup()
	return wfp.Enable(luid, dns)
}

// DisableKillSwitch removes the kill switch, also one left by an earlier
// run or version. Safe to call when nothing is installed.
func DisableKillSwitch() {
	legacyCleanup()
	_ = wfp.Disable()
}

// legacyCleanup removes the Windows Firewall kill switch of earlier versions
// and restores Windows' default policy (outgoing allowed).
func legacyCleanup() {
	_ = fw("set", "allprofiles", "firewallpolicy", "blockinbound,allowoutbound")
	for _, n := range ksRules {
		_ = fw("firewall", "delete", "rule", "name="+ksPrefix+n)
	}
}
