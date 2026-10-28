//go:build !linux

package sockets

import "net/netip"

// Dump is not available on this platform.
func Dump(string, uint32) ([]Socket, error) { return nil, ErrUnsupported }

// ListListening is not available on this platform.
func ListListening() ([]Socket, error) { return nil, ErrUnsupported }

// Resolver knows no owners on this platform.
type Resolver struct{}

// Owner returns an unknown owner.
func (r *Resolver) Owner(uint64) Owner { return Owner{} }

// Of finds nothing on this platform.
func (r *Resolver) Of(string, netip.AddrPort) (Owner, bool) { return Owner{}, false }
