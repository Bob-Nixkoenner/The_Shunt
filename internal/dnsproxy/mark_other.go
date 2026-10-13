//go:build !linux

package dnsproxy

import (
	"errors"
	"syscall"
)

// markControl: packet marks are a Linux thing; another platform's backend
// has to bind upstream sockets to its route instead. Until then upstream
// queries fail (closed) rather than leave the wrong way.
func markControl(uint32) func(string, string, syscall.RawConn) error {
	return func(string, string, syscall.RawConn) error {
		return errors.New("routing DNS upstreams is not implemented on this platform")
	}
}
