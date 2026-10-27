//go:build !linux

package procapp

import "net/netip"

func tcpOwner(netip.AddrPort) string { return Unknown }
