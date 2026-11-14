package socks

import (
	"errors"
	"syscall"
)

// addrInUse: another socket holds the address. Windows reports
// WSAEADDRINUSE (10048), or WSAEACCES (10013) when the other program bound
// it with SO_EXCLUSIVEADDRUSE.
func addrInUse(err error) bool {
	return errors.Is(err, syscall.Errno(10048)) || errors.Is(err, syscall.Errno(10013))
}
