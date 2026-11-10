// Package appwatch puts programs into their route's cgroup as soon as they
// start, so app rules work without `shunt run`.
//
// Exec events come from the kernel's process connector (netlink). It only
// exists in the initial network namespace; elsewhere (tests, containers) a
// /proc scan every 250ms takes over. A slow rescan also runs alongside the
// connector because netlink can drop events under load.
//
// On its own this is best effort: a program could open a socket in the
// short window between exec and the move, and that socket keeps its old
// route (nftables matches the cgroup a socket was created in). The eBPF
// start guard (package racebpf) closes the window where the kernel allows
// it: it marks or refuses those sockets until the watcher has decided
// (Watcher.Decided). Without it, a race-free start needs `shunt run` or a
// menu entry made by `shunt desktop`. Children a program started before
// the move are moved along with it.
package appwatch

import "github.com/Bob-Nixkoenner/the_shunt/internal/config"

// Target is an app rule: processes matching Sels go into cgroup Path.
type Target struct {
	Name string
	Sels []config.AppSel
	Args []string // command line must contain one of these (if any)
	Path string   // cgroup path relative to the mount
}

// Mover moves a process into a cgroup.
type Mover interface {
	Move(rel string, pid int) error
}

// Proc describes a process for the app firewall.
type Proc struct {
	Comm   string
	Exe    string // may be empty (other user's process) – see readProc
	Argv0  string
	Cgroup string
	TTY    bool // has a controlling terminal (started from a shell)
	UID    int
}
