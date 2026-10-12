// Package desktopapp holds the logic of the desktop app (tray + window):
// what state to show, when to notify, icons, autostart. The GTK/WebKit
// window itself lives in cmd/shunt-desktop.
package desktopapp

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/api"
)

// Level is the overall state shown by the tray icon.
type Level int

const (
	OK   Level = iota // protected
	Warn              // a tunnel has no connection (its apps are blocked)
	Bad               // panic mode, or the daemon is not reachable
)

// StaleAfter: WireGuard re-keys every 2 minutes; a handshake older than
// this means the tunnel is not working.
const StaleAfter = 3 * time.Minute

// TunnelLine is one tunnel as shown in the tray menu.
type TunnelLine struct {
	Name string
	OK   bool
	Text string
}

// View is what the tray shows for one daemon status.
type View struct {
	Level   Level
	Title   string // first menu line / tooltip
	Panic   bool
	Tunnels []TunnelLine
	Down    map[string]bool // tunnels without a working connection
	Warn    []string
}

// Compute derives the view from a status (err != nil: daemon unreachable).
func Compute(st *api.Status, err error, now time.Time) View {
	if err != nil || st == nil {
		return View{Level: Bad, Title: "The Shunt service is not reachable", Down: map[string]bool{}}
	}
	v := View{Panic: st.Panic, Down: map[string]bool{}, Warn: st.Warnings}
	for _, t := range st.Tunnels {
		var hs time.Time
		keepalive := false
		for _, p := range t.Peers {
			if p.LastHandshake.After(hs) {
				hs = p.LastHandshake
			}
			keepalive = keepalive || p.KeepaliveSec > 0
		}
		line := TunnelLine{Name: t.Name}
		switch {
		case !t.Up:
			line.Text = t.Name + ": down – its apps are blocked"
		case hs.IsZero():
			line.Text = t.Name + ": no connection yet – its apps are blocked"
		case keepalive && now.Sub(hs) > StaleAfter:
			line.Text = t.Name + ": no connection – its apps are blocked"
		case !keepalive && now.Sub(hs) > StaleAfter:
			line.OK = true
			line.Text = t.Name + ": idle (no keepalive, connects on demand)"
		default:
			line.OK = true
			line.Text = fmt.Sprintf("%s: connected (handshake %s ago)", t.Name, now.Sub(hs).Round(time.Second))
		}
		if !line.OK {
			v.Down[t.Name] = true
		}
		v.Tunnels = append(v.Tunnels, line)
	}
	switch {
	case st.Panic:
		v.Level, v.Title = Bad, "PANIC – all traffic blocked"
	case len(v.Down) > 0:
		names := make([]string, 0, len(v.Down))
		for n := range v.Down {
			names = append(names, n)
		}
		sort.Strings(names)
		v.Level, v.Title = Warn, "No connection: "+strings.Join(names, ", ")+" (blocked, no leak)"
	default:
		v.Level, v.Title = OK, "Protected – default route "+st.DefaultRoute
	}
	return v
}

// Notification is a desktop notification to show.
type Notification struct {
	Summary, Body string
	Urgent        bool
}

// Diff returns the notifications for the change from prev to cur. Brief
// hiccups are not reported: callers pass views that are already debounced
// by StaleAfter.
func Diff(prev, cur View, first bool) []Notification {
	var out []Notification
	if first {
		if cur.Level == Bad && !cur.Panic {
			out = append(out, Notification{"The Shunt is not running", "Apps in a tunnel route are blocked until the service is back.", true})
		}
		return out
	}
	reachable := func(v View) bool { return v.Title != "The Shunt service is not reachable" }
	switch {
	case reachable(prev) && !reachable(cur):
		out = append(out, Notification{"The Shunt service stopped", "Apps in a tunnel route stay blocked (kill switch).", true})
		return out
	case !reachable(prev) && reachable(cur):
		out = append(out, Notification{"The Shunt service is back", cur.Title, false})
	}
	if cur.Panic != prev.Panic {
		if cur.Panic {
			out = append(out, Notification{"PANIC mode on", "All traffic except loopback is blocked.", true})
		} else {
			out = append(out, Notification{"Panic mode off", "Traffic flows again.", false})
		}
	}
	for n := range cur.Down {
		if !prev.Down[n] {
			out = append(out, Notification{"Tunnel " + n + " has no connection", "Its apps are blocked – nothing leaks. The Shunt keeps retrying.", true})
		}
	}
	for n := range prev.Down {
		if !cur.Down[n] && reachable(cur) {
			out = append(out, Notification{"Tunnel " + n + " is back", "", false})
		}
	}
	return out
}
