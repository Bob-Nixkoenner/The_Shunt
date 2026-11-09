package winsplit

import (
	"strings"
	"sync"
	"time"
	"unicode/utf16"
)

// Who asked for a DNS name. Windows' DNS client service (Dnscache, in
// svchost.exe) sends the lookups of every program itself, so the TUN shows
// svchost as the asker and the query would take the default route, also for
// a program on a Tor tunnel or on a tunnel that is down. Windows writes an
// event in the asking process for every lookup it starts
// (Microsoft-Windows-DNS-Client, event 3006); the service reads them
// (dnsetw_windows.go) and keeps the askers of each name here for a while.

const (
	// askKeep: how long an ask is remembered. The DNS client sends the same
	// query again for several seconds when no answer comes; those retries
	// must take the asker's route too.
	askKeep = 15 * time.Second
	// askFresh: an ask this much before the query came in counts as the one
	// that caused it (the DNS client sends within milliseconds).
	askFresh = time.Second
	// askWait: how long a query waits for the event of its asker (events
	// arrive in batches; the watch flushes them when a query comes in).
	askWait = 250 * time.Millisecond

	askMaxNames = 4096
	askPerName  = 8
)

type dnsAsk struct {
	app string    // app ID of the asker (Owners.App)
	at  time.Time // when it asked
}

// askTable keeps the recent askers per name (lower case, no trailing dot).
type askTable struct {
	mu     sync.Mutex
	names  map[string][]dnsAsk
	notify chan struct{} // closed and replaced on every add
}

// normName makes names comparable: lower case, no trailing dot.
func normName(n string) string { return strings.TrimSuffix(strings.ToLower(n), ".") }

func (t *askTable) add(name, app string, at time.Time) {
	name = normName(name)
	if name == "" || app == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.names == nil {
		t.names = map[string][]dnsAsk{}
	}
	if len(t.names) >= askMaxNames {
		t.prune(time.Now())
		if len(t.names) >= askMaxNames {
			clear(t.names)
		}
	}
	l := t.names[name]
	for i, a := range l {
		if a.app == app { // one entry per program, the newest ask
			l = append(l[:i], l[i+1:]...)
			break
		}
	}
	if len(l) >= askPerName {
		l = l[1:]
	}
	t.names[name] = append(l, dnsAsk{app: app, at: at})
	if t.notify != nil {
		close(t.notify)
		t.notify = nil
	}
}

func (t *askTable) prune(now time.Time) {
	for n, l := range t.names {
		keep := l[:0]
		for _, a := range l {
			if now.Sub(a.at) < askKeep {
				keep = append(keep, a)
			}
		}
		if len(keep) == 0 {
			delete(t.names, n)
		} else {
			t.names[n] = keep
		}
	}
}

// get returns the programs that asked for qname within askKeep before now,
// newest first, and whether one of them asked at or after fresh. The DNS
// client appends its search suffixes to short names ("nas" goes out as
// "nas.home.arpa"), so an ask for a leading part of qname counts too.
// changed is closed by the next add.
func (t *askTable) get(qname string, now, fresh time.Time) (apps []string, isFresh bool, changed <-chan struct{}) {
	qname = normName(qname)
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.notify == nil {
		t.notify = make(chan struct{})
	}
	var found []dnsAsk
	for n := qname; n != ""; {
		for _, a := range t.names[n] {
			if now.Sub(a.at) < askKeep {
				found = append(found, a)
			}
		}
		i := strings.LastIndexByte(n, '.')
		if i < 0 {
			break
		}
		n = n[:i]
	}
	// newest first, each program once
	for i := 1; i < len(found); i++ {
		for j := i; j > 0 && found[j].at.After(found[j-1].at); j-- {
			found[j], found[j-1] = found[j-1], found[j]
		}
	}
	seen := map[string]bool{}
	for _, a := range found {
		if !a.at.Before(fresh) {
			isFresh = true
		}
		if !seen[a.app] {
			seen[a.app] = true
			apps = append(apps, a.app)
		}
	}
	return apps, isFresh, t.notify
}

// queryName reads the name a DNS client event starts with (event 3006
// "DNS query is called for the name %1, ..."): UTF-16, zero-terminated.
// "" when it does not look like a host name.
func queryName(data []byte) string {
	var u []uint16
	for i := 0; i+1 < len(data); i += 2 {
		c := uint16(data[i]) | uint16(data[i+1])<<8
		if c == 0 {
			if len(u) == 0 || len(u) > 255 {
				return ""
			}
			s := string(utf16.Decode(u))
			for _, r := range s {
				if r <= ' ' || r == 0x7f || r == '/' || r == '\\' {
					return ""
				}
			}
			return normName(s)
		}
		u = append(u, c)
	}
	return "" // no terminator: cut off
}

// IsDNSClient reports whether app is Windows' DNS client service (it runs in
// svchost.exe and sends the lookups of all programs).
func IsDNSClient(app string) bool {
	if i := strings.LastIndexAny(app, `\/`); i >= 0 {
		app = app[i+1:]
	}
	return strings.EqualFold(app, "svchost.exe")
}
