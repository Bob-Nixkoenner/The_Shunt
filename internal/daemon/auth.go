package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Who may do what through the API socket (members of daemon.socket_group):
//
//   - read status/config, start apps in a route, panic ON: any member.
//     Panic must never wait for a password.
//   - change config, reload, tunnels, panic OFF, and moving a process that
//     already runs in one route into another: "manage" – root, or a user
//     polkit authorizes for org.theshunt.manage (default: admin password,
//     remembered for a few minutes). With daemon.api_auth = "group" every
//     member may manage (the pre-polkit behaviour).
//
// The last point closes an escape: an app forced into a tunnel could
// otherwise call the API itself and move to "direct".

// PolkitAction is the action id in packaging/polkit/org.theshunt.policy.
const PolkitAction = "org.theshunt.manage"

// peer identifies the process on the other end of the socket. start is its
// start time, so a recycled PID is never mistaken for it.
type peer struct {
	pid, uid uint32
	start    string
}

type peerKey struct{}

func connContext(ctx context.Context, c net.Conn) context.Context {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return ctx
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return ctx
	}
	var cred *unix.Ucred
	_ = raw.Control(func(fd uintptr) {
		cred, _ = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if cred == nil {
		return ctx
	}
	p := &peer{pid: uint32(cred.Pid), uid: cred.Uid}
	p.start, _ = procStart(int(cred.Pid))
	return context.WithValue(ctx, peerKey{}, p)
}

func peerOf(ctx context.Context) *peer {
	p, _ := ctx.Value(peerKey{}).(*peer)
	return p
}

// procStart returns field 22 of /proc/<pid>/stat (start time in ticks).
func procStart(pid int) (string, error) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return "", err
	}
	// the command name (field 2) may contain spaces and parentheses
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return "", errors.New("bad stat")
	}
	f := strings.Fields(s[i+1:])
	if len(f) < 20 {
		return "", errors.New("bad stat")
	}
	return f[19], nil // field 22 overall
}

// alive reports whether the peer process still exists (same start time).
func (p *peer) alive() bool {
	s, err := procStart(int(p.pid))
	return err == nil && s == p.start && p.start != ""
}

var errForbidden = errors.New("forbidden")

// authorize checks the manage permission.
func (d *Daemon) authorize(ctx context.Context, p *peer) error {
	if p == nil {
		return fmt.Errorf("%w: no peer credentials", errForbidden)
	}
	if p.uid == 0 {
		return nil
	}
	d.mu.Lock()
	mode := d.cfg.Daemon.APIAuth
	d.mu.Unlock()
	if mode == "group" {
		return nil
	}
	pk, err := exec.LookPath("pkcheck")
	if err != nil {
		return fmt.Errorf("%w: this needs root (sudo) or polkit (package polkitd); or set daemon.api_auth = \"group\"", errForbidden)
	}
	if !p.alive() {
		return fmt.Errorf("%w: caller is gone", errForbidden)
	}
	// Interactive: the desktop's polkit agent asks for the password.
	cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(cctx, pk, "--action-id", PolkitAction,
		"--process", fmt.Sprintf("%d,%s,%d", p.pid, p.start, p.uid), "--allow-user-interaction")
	if out, err := cmd.CombinedOutput(); err != nil {
		d.Log.Info("polkit denied", "uid", p.uid, "pid", p.pid, "out", strings.TrimSpace(string(out)))
		return fmt.Errorf("%w: not authorized (polkit). Run with sudo or authenticate in the password dialog", errForbidden)
	}
	return nil
}
