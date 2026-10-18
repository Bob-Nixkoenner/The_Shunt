package desktopapp

import (
	"fmt"
	"net"
	"os"
	"time"
)

// Single makes sure only one desktop app runs per user. The first
// instance listens on an abstract unix socket (no file, gone with the
// process); later starts ask it to show its window and exit.
type Single struct {
	ln net.Listener
}

// socketName is a variable so tests don't talk to a running app.
var socketName = defaultSocketName

// Claim returns a Single if this is the first instance, or nil after it
// has asked the running instance to show itself.
func Claim() (*Single, error) {
	ln, err := net.Listen("unix", socketName())
	if err == nil {
		return &Single{ln: ln}, nil
	}
	c, derr := net.Dial("unix", socketName())
	if derr != nil {
		// a socket file left by a crash (not an abstract socket): remove, retry once
		if rerr := os.Remove(socketName()); rerr == nil {
			if ln, err := net.Listen("unix", socketName()); err == nil {
				return &Single{ln: ln}, nil
			}
		}
		return nil, fmt.Errorf("another instance seems to run but does not answer: %w", err)
	}
	defer c.Close()
	_, _ = c.Write([]byte("show\n"))
	return nil, nil
}

// Requests calls show for every later start of the app.
func (s *Single) Requests(show func()) {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		// only the same user can reach it: check the peer's uid
		if uc, ok := c.(*net.UnixConn); ok && peerUID(uc) == os.Getuid() {
			show()
		}
		c.Close()
	}
}

// WaitFree blocks until no instance answers on the socket (or 10 s passed):
// a restarting app starts its successor first and exits right after, and
// the successor must not mistake the dying instance for a running one.
func WaitFree() {
	for range 50 {
		c, err := net.Dial("unix", socketName())
		if err != nil {
			return
		}
		c.Close()
		time.Sleep(200 * time.Millisecond)
	}
}
