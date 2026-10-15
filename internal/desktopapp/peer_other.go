//go:build !linux

package desktopapp

import (
	"net"
	"os"
)

// peerUID: no peer credentials here; on Windows the socket file's location
// (the user's profile) is the access control.
func peerUID(*net.UnixConn) int { return os.Getuid() }
