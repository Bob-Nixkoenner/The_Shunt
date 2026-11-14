package winsplit

import (
	"fmt"
	"log"
	"net/netip"
	"os/exec"
	"strings"
	"sync"

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
// "block outbound" policy; legacyCleanup removes them (killswitch_legacy.go).

func fw(args ...string) error {
	if out, err := exec.Command("netsh", append([]string{"advfirewall"}, args...)...).CombinedOutput(); err != nil {
		return fmt.Errorf("netsh advfirewall %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// EnableKillSwitch installs the kill switch for the adapter with LUID luid
// (replacing an earlier one). dns is the only DNS server apps may ask.
func EnableKillSwitch(luid uint64, dns netip.Addr, apps ...string) error {
	legacyCleanup()
	return wfp.Enable(luid, dns, apps...)
}

// DisableKillSwitch removes the kill switch, also one left by an earlier
// run or version. Safe to call when nothing is installed.
func DisableKillSwitch() {
	legacyCleanup()
	_ = wfp.Disable()
}

// legacyCleanup removes the Windows Firewall kill switch of earlier versions
// and, only if it was there, restores Windows' default policy (outgoing
// allowed); a policy the user set is left alone (report L-07). Once per
// process: the old version cannot add its rules again while this one runs.
func legacyCleanup() {
	legacyOnce.Do(func() {
		if legacyCleanupWith(fw) {
			log.Print("kill switch: removed the Windows Firewall kill switch of an earlier version, outgoing policy allowed again")
		}
	})
}

var legacyOnce sync.Once
