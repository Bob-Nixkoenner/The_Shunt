// Package sockets lists the machine's TCP and UDP sockets and tells which
// program owns one. The owner comes from the socket's cgroup (sock_diag
// reports it), not from /proc/<pid>/fd: shuntd lacks CAP_SYS_PTRACE and
// cannot read other users' file descriptors.
//
// Linux only; elsewhere the functions return ErrUnsupported.
package sockets

import (
	"errors"
	"net/netip"
	"path"
	"strings"
)

// ErrUnsupported: no socket listing on this platform.
var ErrUnsupported = errors.New("socket listing is not supported on this platform")

// Socket is one TCP or UDP socket.
type Socket struct {
	Proto  string // "tcp" or "udp"
	Local  netip.AddrPort
	Remote netip.AddrPort
	State  uint8 // kernel TCP state (UDP: StateClose = unconnected)
	UID    uint32
	Inode  uint32
	Cgroup uint64 // cgroup v2 id (inode of its directory), 0 = unknown
	Iface  int    // SO_BINDTODEVICE, 0 = any
	// V6Only: an IPv6 socket on :: that does not take IPv4 too.
	V6Only bool
}

// Kernel socket states sock_diag reports.
const (
	StateEstablished = 1
	StateClose       = 7
	StateListen      = 10
)

// Listening reports whether s waits for connections or datagrams from
// anywhere: a listening TCP socket or an unconnected UDP socket.
func (s Socket) Listening() bool {
	if s.Proto == "tcp" {
		return s.State == StateListen
	}
	return s.State == StateClose && s.Remote.Port() == 0
}

// Owner names what a socket belongs to.
type Owner struct {
	// Name: the program or service, e.g. "firefox", "flatpak:im.riot.Riot",
	// "snap:brave", "ssh". "" = unknown.
	Name string `json:"name"`
	// Unit: the systemd unit (scope/service) or Shunt group, "" = none.
	Unit string `json:"unit,omitempty"`
	// Cgroup: the cgroup path below the mount.
	Cgroup string `json:"cgroup,omitempty"`
	// Procs: the distinct program names running in that cgroup (a few).
	Procs []string `json:"procs,omitempty"`
	// System: a system service (not part of a user session).
	System bool `json:"system,omitempty"`
	// Shared: the cgroup holds unrelated programs (a login session, a
	// Shunt route group); Name is then a guess.
	Shared bool `json:"shared,omitempty"`
}

// launchers put their own name before the app id in a scope name
// (app-gnome-firefox-1234.scope).
var launchers = map[string]bool{"gnome": true, "cosmic": true, "kde": true, "xfce": true, "xfce4": true, "mate": true, "cinnamon": true, "lxqt": true, "budgie": true, "sway": true, "hyprland": true, "niri": true}

// shuntApps is where shuntd keeps the cgroups of routed apps.
const shuntApps = "system.slice/shuntd.service/apps/"

// nameOf derives an owner from a cgroup path: the innermost systemd unit
// names the app (app-cosmic-discord-7187.scope -> discord). generic: the
// name says nothing about the program (a login session, a Shunt route
// group), the caller should prefer the processes' names.
func nameOf(cg string) (o Owner, generic bool) {
	o = Owner{Cgroup: cg, System: strings.HasPrefix(cg, "system.slice/") || cg == "init.scope"}
	if g, ok := strings.CutPrefix(cg, shuntApps); ok {
		o.Unit = "shunt:" + g
		return o, true
	}
	parts := strings.Split(cg, "/")
	for i := len(parts) - 1; i >= 0; i-- {
		p := parts[i]
		if strings.HasSuffix(p, ".scope") || strings.HasSuffix(p, ".service") || strings.HasSuffix(p, ".socket") {
			o.Unit = unescape(p)
			break
		}
	}
	if o.Unit == "" {
		return o, true
	}
	n := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(o.Unit, ".scope"), ".service"), ".socket")
	switch {
	case n == "init":
		o.Name = "systemd"
		return o, false
	case strings.HasPrefix(n, "session-"):
		// a login session: on desktops that start apps without a scope of
		// their own (COSMIC) the whole desktop lives here
		o.Name = "login session"
		return o, true
	case strings.HasPrefix(n, "user@") || strings.HasPrefix(n, "user-runtime-dir@"):
		return o, true
	case strings.HasPrefix(n, "snap."):
		// snap.firefox.firefox-<uuid>
		f := strings.Split(n, ".")
		if len(f) >= 2 {
			o.Name = "snap:" + f[1]
		}
		return o, false
	}
	app, isApp := strings.CutPrefix(n, "app-")
	if !isApp {
		o.Name, _, _ = strings.Cut(n, "@")
		return o, false
	}
	app, _, _ = strings.Cut(app, "@")
	if i := strings.LastIndexByte(app, '-'); i > 0 && allDigits(app[i+1:]) {
		app = app[:i]
	}
	if id, ok := strings.CutPrefix(app, "flatpak-"); ok {
		o.Name = "flatpak:" + id
		return o, false
	}
	if l, rest, ok := strings.Cut(app, "-"); ok && launchers[l] {
		app = rest
	}
	// reverse-DNS desktop ids: org.kde.konsole -> konsole
	if strings.Count(app, ".") >= 2 {
		app = path.Ext(app)[1:]
	}
	o.Name = app
	return o, app == ""
}

func allDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}

// unescape undoes systemd's \xNN escaping in unit names.
func unescape(s string) string {
	if !strings.Contains(s, `\x`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) && s[i+1] == 'x' {
			if v, ok := hexByte(s[i+2 : i+4]); ok {
				b.WriteByte(v)
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func hexByte(h string) (byte, bool) {
	var v byte
	for _, c := range []byte(h) {
		switch {
		case c >= '0' && c <= '9':
			v = v<<4 | (c - '0')
		case c >= 'a' && c <= 'f':
			v = v<<4 | (c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			v = v<<4 | (c - 'A' + 10)
		default:
			return 0, false
		}
	}
	return v, true
}
