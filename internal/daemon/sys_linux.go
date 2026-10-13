package daemon

import (
	"net"

	"golang.org/x/sys/unix"
)

// selfExe is shuntd's own binary, also after an update replaced the file.
func selfExe() string { return "/proc/self/exe" }

// listenPrivate creates the API socket accessible by root only (the
// caller then opens it up for the socket group).
func listenPrivate(sock string) (net.Listener, error) {
	old := unix.Umask(0o177)
	defer unix.Umask(old)
	return net.Listen("unix", sock)
}

// peerCred returns the pid and uid of the process on the other end of a
// unix socket (SO_PEERCRED, set by the kernel: cannot be faked).
func peerCred(c net.Conn) (pid, uid uint32, ok bool) {
	uc, isUnix := c.(*net.UnixConn)
	if !isUnix {
		return 0, 0, false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, 0, false
	}
	var cred *unix.Ucred
	_ = raw.Control(func(fd uintptr) {
		cred, _ = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if cred == nil {
		return 0, 0, false
	}
	return uint32(cred.Pid), cred.Uid, true
}
