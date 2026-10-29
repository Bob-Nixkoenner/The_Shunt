//go:build !linux

package daemon

import (
	"net"
	"os"
)

func selfExe() string {
	exe, _ := os.Executable()
	return exe
}

func listenPrivate(sock string) (net.Listener, error) { return net.Listen("unix", sock) }

// peerCred: unknown peers get nothing that needs credentials.
func peerCred(net.Conn) (pid, uid uint32, ok bool) { return 0, 0, false }

func otherFirewalls() []string { return nil }

func physicalIface(string) bool { return false }

func tcpTimestamps() string { return "" }

func setTCPTimestamps(string) error { return nil }
