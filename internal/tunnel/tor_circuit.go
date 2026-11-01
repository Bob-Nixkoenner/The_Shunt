//go:build linux || windows

package tunnel

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// controlExchange authenticates on tor's control connection with cookie and
// runs cmds; it returns the reply lines without their status prefix. A data
// reply ("250+key=" ... ".") yields "key=" and then its lines as they are.
// ControlExchange is controlExchange for other tors (internal/splitstack).
func ControlExchange(c net.Conn, cookie []byte, cmds []string) ([]string, error) {
	return controlExchange(c, cookie, cmds)
}

func controlExchange(c net.Conn, cookie []byte, cmds []string) ([]string, error) {
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	rd := bufio.NewReader(c)
	var out []string
	send := func(cmd string) error {
		if _, err := fmt.Fprintf(c, "%s\r\n", cmd); err != nil {
			return err
		}
		data := false
		for {
			l, err := rd.ReadString('\n')
			if err != nil {
				return err
			}
			l = strings.TrimRight(l, "\r\n")
			if data {
				if l == "." {
					data = false
				} else {
					out = append(out, l)
				}
				continue
			}
			if len(l) < 4 {
				continue
			}
			out = append(out, l[4:])
			if l[3] == '+' {
				data = true
				continue
			}
			if l[3] == ' ' { // last line of the reply
				if l[0] != '2' {
					return errors.New(l[4:])
				}
				return nil
			}
		}
	}
	if err := send("AUTHENTICATE " + hex.EncodeToString(cookie)); err != nil {
		return nil, err
	}
	out = nil
	for _, cmd := range cmds {
		if err := send(cmd); err != nil {
			return out, err
		}
	}
	return out, nil
}

// TorCircuit is the circuit a Tor tunnel's traffic currently uses. It is
// shown on this computer only (the exit relay's address is not for sharing).
type TorCircuit struct {
	Hops    int    `json:"hops"`              // relays on the path, a bridge counts as the first
	Bridge  bool   `json:"bridge,omitempty"`  // the first hop is a bridge
	Country string `json:"country,omitempty"` // exit, two letters ("de")
	Relay   string `json:"relay,omitempty"`   // exit nickname
	IP      string `json:"ip,omitempty"`      // exit address
}

// circuitCache keeps the answer for a few seconds: the status is polled.
var circuitCache sync.Map // *Tor -> circuitEntry

type circuitEntry struct {
	at time.Time
	c  *TorCircuit
}

// Circuit returns the circuit new connections of this tunnel use (nil: not
// connected or none built yet).
func (t *Tor) Circuit() *TorCircuit {
	if v, ok := circuitCache.Load(t); ok {
		if e := v.(circuitEntry); time.Since(e.at) < 4*time.Second {
			return e.c
		}
	}
	t.mu.Lock()
	run := t.running
	t.mu.Unlock()
	var c *TorCircuit
	if run {
		var since time.Time
		if v, ok := newnymAt.Load(t); ok {
			since = v.(time.Time)
		}
		c, _ = queryCircuit(t.control, len(t.spec.Bridges) > 0, since)
	}
	circuitCache.Store(t, circuitEntry{time.Now(), c})
	return c
}

// newnymAt: when a Tor last got NEWNYM. Circuits built before it are dirty:
// they keep their open connections, but new ones never use them again.
var newnymAt sync.Map // *Tor -> time.Time

// markNewnym records a NEWNYM and drops the cached circuit, so the next
// status shows the path new connections take from now on.
func markNewnym(t *Tor) {
	newnymAt.Store(t, time.Now().UTC())
	circuitCache.Delete(t)
}

// QueryCircuit is queryCircuit for other tors (the one the Android app
// brings along, internal/splitstack).
func QueryCircuit(ctl func(...string) ([]string, error), bridges bool, since time.Time) (*TorCircuit, error) {
	return queryCircuit(ctl, bridges, since)
}

// queryCircuit asks tor (ctl runs control commands) for the circuit the
// tunnel's connections take: the one carrying most open streams, else the
// newest general one; circuits from before the last NEWNYM (since) do not
// count. Tor gives every app its own circuits (IsolateSOCKSAuth), so this is
// the busiest exit, not the only one.
func queryCircuit(ctl func(...string) ([]string, error), bridges bool, since time.Time) (*TorCircuit, error) {
	lines, err := ctl("GETINFO circuit-status", "GETINFO stream-status")
	if err != nil {
		return nil, err
	}
	path := pickCircuit(lines, since)
	if len(path) == 0 {
		return nil, nil
	}
	c := &TorCircuit{Hops: len(path), Bridge: bridges}
	fp, nick, _ := strings.Cut(strings.TrimPrefix(path[len(path)-1], "$"), "~")
	c.Relay = nick
	if fp == "" || strings.ContainsAny(fp, " \r\n") {
		return c, nil
	}
	if ns, err := ctl("GETINFO ns/id/" + fp); err == nil {
		for _, l := range ns {
			if f := strings.Fields(l); len(f) >= 7 && f[0] == "r" {
				c.IP = f[6]
				if c.Relay == "" {
					c.Relay = f[1]
				}
			}
		}
	}
	if net.ParseIP(c.IP) != nil {
		if cc, err := ctl("GETINFO ip-to-country/" + c.IP); err == nil {
			for _, l := range cc {
				if _, v, ok := strings.Cut(l, "="); ok && len(strings.TrimSpace(v)) == 2 && v != "??" {
					c.Country = strings.ToLower(strings.TrimSpace(v))
				}
			}
		}
	}
	return c, nil
}

// pickCircuit reads the circuit-status and stream-status lines and returns
// the relays ("$FP~nick") of the chosen BUILT general circuit with an exit
// (not internal), built after since (zero: any).
func pickCircuit(lines []string, since time.Time) []string {
	type circ struct {
		path    []string
		created string
	}
	circs := map[string]*circ{}
	var order []string
	used := map[string]int{} // circuit -> open streams on it
	for _, l := range lines {
		f := strings.Fields(l)
		switch {
		case len(f) >= 3 && f[1] == "BUILT" && strings.HasPrefix(f[2], "$"):
			c := &circ{path: strings.Split(f[2], ",")}
			general, internal := false, false
			for _, kv := range f[3:] {
				switch k, v, _ := strings.Cut(kv, "="); k {
				case "PURPOSE":
					// conflux: newer tor carries exit streams on linked pairs (same exit)
					general = v == "GENERAL" || v == "CONFLUX_LINKED"
				case "TIME_CREATED":
					c.created = v
				case "BUILD_FLAGS":
					internal = strings.Contains(v, "IS_INTERNAL") // onion/directory use: no exit
				}
			}
			if !since.IsZero() {
				if tc, err := time.Parse("2006-01-02T15:04:05.999999", c.created); err != nil || tc.Before(since) {
					general = false // dirty since NEWNYM: new connections never take it
				}
			}
			if general && !internal {
				circs[f[0]] = c
				order = append(order, f[0])
			}
		case len(f) == 4 && f[1] == "SUCCEEDED" && f[2] != "0": // id status circuit target
			used[f[2]]++
		}
	}
	sort.SliceStable(order, func(i, j int) bool {
		a, b := circs[order[i]], circs[order[j]]
		if ua, ub := used[order[i]], used[order[j]]; ua != ub {
			return ua > ub // the one most open connections take
		}
		return a.created > b.created
	})
	if len(order) == 0 {
		return nil
	}
	return circs[order[0]].path
}
