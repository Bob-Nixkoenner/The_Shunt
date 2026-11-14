//go:build !windows

package socks

import (
	"errors"
	"syscall"
)

// addrInUse: another socket holds the address.
func addrInUse(err error) bool { return errors.Is(err, syscall.EADDRINUSE) }
