package defense

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Tempo detection: agent frameworks run scan, connect and login in one go,
// at machine speed. The chain "scan finding -> handshake with a decoy ->
// login try" from one source within a few seconds is reported as
// KindAutomatedChain (high).
//
// Thresholds, from the lab runs R01 (nmap SYN + connect scan, 1024 ports at
// 500/s against the decoys) and R02 (scripted telnet/ssh logins):
//   - R01: the whole scan took 11 s; the first full handshake came 6.3 s
//     after the scan finding. A scripted login right after such a scan lands
//     within about 12 s. ChainWindow = 20 s leaves room for a slower scan.
//   - R02: from the handshake to the first login try took about 1 ms
//     (telnet); an SSH key exchange adds well under a second. A person who
//     types a user name and a password needs several seconds. ChainLoginGap
//     = 3 s.
//   - R02 has no scan finding (only two ports) and must give no chain; R01
//     has no login and must give none either.
//
// Only events that passed the ignore list count (defense.ignore), and scan
// findings never come from replies to this machine's own connections (see
// "Ignored devices" in docs/DEFENSE.md), so neither can start a chain.
const (
	ChainWindow   = 20 * time.Second
	ChainLoginGap = 3 * time.Second
	chainMax      = 4096
)

type chainEntry struct {
	scan    time.Time // last scan finding
	connect time.Time // last finished handshake with a decoy
}

type chainState struct {
	mu sync.Mutex
	m  map[netip.Addr]*chainEntry
}

// chainHit is a finished chain, reported by the manager.
type chainHit struct {
	src                    netip.Addr
	port                   int
	via                    string
	scanToLogin, connLogin time.Duration
}

// isLoginEvent reports whether ev is a login try on a decoy and names how.
func isLoginEvent(ev Event) (via string, ok bool) {
	switch ev.Kind {
	case KindBait:
		return "bait", true
	case KindCowrie:
		if v, _, found := strings.Cut(ev.Detail, " login user="); found && !strings.Contains(v, " ") {
			return v, true
		}
	}
	return "", false
}

// step feeds one reported event; it returns a finished chain, if any.
func (c *chainState) step(ev Event, now time.Time) (chainHit, bool) {
	isScan := ev.Kind == KindScan
	isConnect := ev.Kind == KindDecoyHit && ev.Detail == "tcp connect"
	via, isLogin := isLoginEvent(ev)
	if !isScan && !isConnect && !isLogin {
		return chainHit{}, false
	}
	src, err := netip.ParseAddr(ev.Src)
	if err != nil {
		return chainHit{}, false
	}
	src = src.Unmap()
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.m[src]
	if e != nil && now.Sub(e.scan) > ChainWindow {
		delete(c.m, src)
		e = nil
	}
	switch {
	case isScan:
		if e == nil {
			if c.m == nil {
				c.m = map[netip.Addr]*chainEntry{}
			}
			if len(c.m) >= chainMax {
				c.pruneLocked(now)
				if len(c.m) >= chainMax {
					return chainHit{}, false
				}
			}
			e = &chainEntry{scan: now}
			c.m[src] = e
		}
	case isConnect:
		if e != nil { // only sources that scanned are followed
			e.connect = now
		}
	case isLogin:
		if e == nil || e.connect.IsZero() || now.Sub(e.connect) > ChainLoginGap {
			return chainHit{}, false
		}
		delete(c.m, src) // once per chain
		return chainHit{src: src, port: ev.Port, via: via, scanToLogin: now.Sub(e.scan), connLogin: now.Sub(e.connect)}, true
	}
	return chainHit{}, false
}

func (c *chainState) pruneLocked(now time.Time) {
	for k, e := range c.m {
		if now.Sub(e.scan) > ChainWindow {
			delete(c.m, k)
		}
	}
}

func (c *chainState) prune(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked(now)
}

func (c *chainState) reset() {
	c.mu.Lock()
	c.m = nil
	c.mu.Unlock()
}

func (c *chainState) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.m)
}

// chainFound reports a finished chain and blocks the source when blocking of
// login attempts is on (the source finished a handshake: nothing waits).
func (m *Manager) chainFound(h chainHit) {
	m.Report(Event{Kind: KindAutomatedChain, Severity: SevHigh, Src: h.src.String(), Port: h.port, Proto: "tcp",
		Detail: fmt.Sprintf("scan_to_login=%.1fs connect_to_login=%dms via=%s", h.scanToLogin.Seconds(), h.connLogin.Milliseconds(), h.via)})
	m.maybeBan(h.src, KindAutomatedChain, FeatBrute)
}
