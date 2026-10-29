// Package procapp finds which program owns a local TCP connection (used to
// give each app its own Tor circuits and to name SOCKS traffic).
package procapp

import "net/netip"

// Unknown is the name returned when the owner cannot be found.
const Unknown = "unknown"

// TCP returns the program name (/proc/<pid>/comm) of the process that owns
// the local end of a TCP connection from the loopback address a.
func TCP(a netip.AddrPort) string { return tcpOwner(a) }
