package daemon

import (
	"context"
	"log/slog"

	"github.com/Bob-Nixkoenner/the_shunt/internal/appwatch"
	"github.com/Bob-Nixkoenner/the_shunt/internal/dnsproxy"
	"github.com/Bob-Nixkoenner/the_shunt/internal/engine"
	"github.com/Bob-Nixkoenner/the_shunt/internal/firewall"
)

// Backend is what the daemon needs from the operating system to enforce a
// plan: process groups, packet rules, policy routing and a view of the
// processes. backend_linux.go does it with cgroup v2, nftables and netlink;
// another platform brings its own. Tunnels, network detection, links and
// DNS upstreams are portable packages with per-platform files of their own.
type Backend interface {
	// Init prepares process grouping and returns the group shuntd runs in
	// (the default group root).
	Init() (self string, err error)
	// Groups manages the plan's process groups (paths from the plan).
	Groups() firewall.CGroups

	// Render compiles a plan into the platform's ruleset (`shuntd check`
	// prints it). Apply installs a rendered ruleset together with the app
	// firewall's held groups in one step: nothing held gets out between.
	Render(p *engine.Plan) (string, error)
	Apply(ruleset string, held map[string]engine.Group) error
	// Hold replaces the app firewall's blocked waiting groups (id -> group).
	Hold(held map[string]engine.Group) error
	// WatchHeld reports the first packets of held groups until ctx ends.
	WatchHeld(ctx context.Context, seen func(id string, uid int)) error

	// SyncRoutes makes the kill switch and tunnel/link routing match the
	// plan; ifaceUp tells which tunnel interfaces exist right now.
	SyncRoutes(p *engine.Plan, ifaceUp map[string]bool) error
	Panic(on bool) error
	// ForgetTCP drops the connection tracking of TCP flows carrying a
	// route mark, so their next packets are classified again (TCP is
	// sticky otherwise; used when a pass ends).
	ForgetTCP(mark uint32) (int, error)
	// Stopped adapts the ruleset for the time shuntd is down: tunnels stay
	// blocked, direct traffic (DNS included) goes on.
	Stopped(p *engine.Plan) error
	// LiftLockdown ends the boot lockdown once the plan is in place.
	LiftLockdown() error
	// Cleanup removes every trace (lifts all kill switches).
	Cleanup() error

	// DomainSets stores the addresses domain rules resolved to.
	DomainSets() dnsproxy.SetWriter
	// Watcher moves programs into their app rule's group when they start;
	// unknown gets the ones no rule matched (app firewall).
	Watcher(log *slog.Logger, unknown func(pid int, p appwatch.Proc)) AppWatcher

	// CgroupOf returns the group path pid runs in, Comm its name, Pids all
	// running processes.
	CgroupOf(pid int) (string, bool)
	Comm(pid int) (string, bool)
	Pids() []int
}

// AppWatcher follows program starts (see appwatch.Watcher).
type AppWatcher interface {
	SetTargets(t []appwatch.Target, skip string)
	SetRecheck(prefix string)
	Place(pid int, path string)
	Run(stop <-chan struct{})
}
