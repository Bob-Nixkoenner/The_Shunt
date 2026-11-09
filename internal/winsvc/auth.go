package winsvc

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"
)

// Who may do what through the API socket (the Windows counterpart of
// internal/daemon/auth.go):
//
//   - read status/config/history/processes, check a config, probe a route,
//     new Tor circuits, panic ON, end a pass: every local user. Panic must
//     never wait for anyone.
//   - change config, import/delete tunnels, reload, restart, panic OFF,
//     pass > 0 and moving a process into a route: "manage" – SYSTEM, an
//     elevated Administrator or a member of the local manage group
//     (daemon.socket_group, default "shunt"; the installer creates it and
//     adds the installing user).
//   - exception: anyone may start their own app in a route (POST /v1/run
//     for a child of the calling process that the caller just started),
//     unless that leaves the route the caller itself runs in (escape).
//
// The service learns the caller from the socket (peer PID, then that
// process's token); a caller it cannot identify may only read.

// DefaultManageGroup is the local group whose members may manage when
// daemon.socket_group is empty. Not "shunt": a local group cannot share its
// name with a user account, and an account named like the program is common.
const DefaultManageGroup = "The Shunt Managers"

// Caller is the process on the other end of the API socket.
type Caller struct {
	PID int
	// Created is the process's creation time (a recycled PID is never
	// mistaken for it).
	Created time.Time
	// User names the account (for the log).
	User string
	// Manage: SYSTEM, elevated Administrator or member of the manage group.
	Manage bool
}

type callerKey struct{}

// WithCaller returns ctx carrying c (Server.Identify does this per
// connection; tests use it directly).
func WithCaller(ctx context.Context, c *Caller) context.Context {
	return context.WithValue(ctx, callerKey{}, c)
}

// CallerOf returns the caller of a request, nil = unknown.
func CallerOf(ctx context.Context) *Caller {
	c, _ := ctx.Value(callerKey{}).(*Caller)
	return c
}

// ErrForbidden: the caller may not do this (HTTP 403).
var ErrForbidden = errors.New("forbidden")

// ProcInfo describes a process for the /v1/run check.
type ProcInfo struct {
	Parent  int
	Created time.Time
}

func (s *Server) manageGroup() string {
	if s.ManageGroup != "" {
		return s.ManageGroup
	}
	return DefaultManageGroup
}

// authorize checks the manage permission for what (a short description for
// the error and the log).
func (s *Server) authorize(r *http.Request, what string) error {
	c := CallerOf(r.Context())
	if c == nil {
		log.Printf("api: %s denied: caller unknown", what)
		return fmt.Errorf("%w: %s: the service cannot tell who is calling (needs Windows 10 1809 or newer)", ErrForbidden, what)
	}
	if c.Manage {
		return nil
	}
	log.Printf("api: %s denied: pid %d user %s", what, c.PID, c.User)
	return fmt.Errorf("%w: %s needs an administrator (run as administrator) or a member of the local group %q", ErrForbidden, what, s.manageGroup())
}

// may answers 403 and returns false when the caller may not manage.
func (s *Server) may(w http.ResponseWriter, r *http.Request, what string) bool {
	if err := s.authorize(r, what); err != nil {
		fail(w, http.StatusForbidden, err)
		return false
	}
	return true
}

// authorizeRun decides POST /v1/run: managers may put any process into any
// route; others only a process they just started themselves (a direct child,
// younger than the caller), and not out of the route the caller or the
// process already runs in (except into block).
func (s *Server) authorizeRun(r *http.Request, pid int, route string) error {
	c := CallerOf(r.Context())
	if c != nil && c.Manage {
		return nil
	}
	if c == nil || s.ProcInfo == nil {
		return s.authorize(r, "starting an app in a route")
	}
	pi, err := s.ProcInfo(pid)
	if err != nil || pi.Parent != c.PID || pi.Created.Before(c.Created) {
		log.Printf("api: run pid %d denied: not a child of pid %d (user %s)", pid, c.PID, c.User)
		return fmt.Errorf("%w: process %d was not started by the caller", ErrForbidden, pid)
	}
	if s.RouteOf != nil && route != "block" {
		for _, from := range []string{s.RouteOf(c.PID), s.RouteOf(pid)} {
			if from != "" && from != route {
				return s.authorize(r, "leaving route "+from)
			}
		}
	}
	return nil
}
