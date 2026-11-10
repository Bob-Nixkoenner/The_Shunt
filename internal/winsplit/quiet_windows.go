//go:build windows

package winsplit

import "github.com/Bob-Nixkoenner/the_shunt/internal/winsplit/wfp"

// EnableQuiet drops outgoing discovery traffic (NetBIOS, LLMNR, mDNS, SSDP,
// WS-Discovery, KDE Connect, Syncthing, multicast, broadcast incl. subnet
// broadcasts; DHCP and IPv6 neighbour discovery stay) with persistent WFP
// filters and their boot-time copies. The set does not depend on the
// network.
func EnableQuiet() error { return wfp.EnableQuiet() }

// EnableQuietBoot puts the same filters back for the next boot (at
// shutdown); they would normally still be there.
func EnableQuietBoot() error { return wfp.EnableQuiet() }

// DisableQuiet removes the quiet-mode filters (also one left by an earlier
// run). Safe to call when nothing is installed.
func DisableQuiet() {
	_ = wfp.DisableQuiet()
	_ = QuietSourceRestore() // LLMNR/mDNS/NetBIOS registry values back
}
