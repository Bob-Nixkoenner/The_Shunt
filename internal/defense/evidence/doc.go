// Package evidence keeps a tamper-evident local record of defense events
// and, on Linux, a small packet capture of unsolicited inbound traffic and
// link-layer control frames. It is built for one purpose: to hand a case to
// an authority or a lawyer when the user decides to.
//
// Rules (see docs/DEFENSE.md, "Evidence"):
//   - Everything stays on this machine (files 0600, directories 0700).
//     Nothing is sent anywhere without an action of the user (export,
//     abuse lookup, optional time stamp).
//   - The Shunt never scans back. It only records what reached it.
//   - Never recorded: the name, SSID, BSSID or MAC of the own network, own
//     addresses, passwords, normal outgoing or established traffic.
//   - No test or fixture may contain real network data (use 192.0.2.0/24,
//     198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32).
//
// The package does not import package defense (the manager calls into it
// through a hook), so it can be used by the CLI on its own.
package evidence
