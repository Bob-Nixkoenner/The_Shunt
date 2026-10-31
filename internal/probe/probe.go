// Package probe implements the leak self-test: for every route a probe
// process is started inside that route and reports which public IP and
// which DNS resolver the outside world sees.
//
// The probe contacts two third parties: api.ipify.org (public IP) and
// Google's o-o.myaddr.l.google.com (which resolver asked). Callers must
// make that clear to the user before running it.
package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// IPURL answers with the caller's public IP as plain text.
// SHUNT_PROBE_IP_URL overrides it (used by the integration test).
var IPURL = "https://api.ipify.org"

func init() {
	if u := os.Getenv("SHUNT_PROBE_IP_URL"); u != "" {
		IPURL = u
	}
}

// DNSName answers TXT queries with the address of the resolver that asked.
const DNSName = "o-o.myaddr.l.google.com"

// Result is what one probe saw.
type Result struct {
	IP       string `json:"ip,omitempty"`
	IPErr    string `json:"ip_error,omitempty"`
	Resolver string `json:"resolver,omitempty"`
	DNSErr   string `json:"dns_error,omitempty"`
	// Tor: the probe ran in a Tor route. Tor's DNS port cannot answer the
	// TXT query that shows the resolver, so it was not asked; IsTor (answer
	// of check.torproject.org) takes its place. TorErr: why there is none.
	Tor    bool   `json:"tor,omitempty"`
	IsTor  bool   `json:"is_tor,omitempty"`
	TorErr string `json:"tor_error,omitempty"`
}

// TorURL answers {"IsTor":true,...} for a request that came out of Tor.
// SHUNT_PROBE_TOR_URL overrides it (used by tests).
var TorURL = "https://check.torproject.org/api/ip"

func init() {
	if u := os.Getenv("SHUNT_PROBE_TOR_URL"); u != "" {
		TorURL = u
	}
}

// RunTor is Run for a Tor route: the public IP plus check.torproject.org
// instead of the resolver query (Tor's DNSPort refuses TXT lookups).
func RunTor(ctx context.Context) Result { return run(ctx, nil, nil, true, 8*time.Second) }

// RunTorWith is RunTor through dial (a Tor route of an engine that makes its
// connections itself), with its own limit per request.
func RunTorWith(ctx context.Context, dial Dial, limit time.Duration) Result {
	return run(ctx, dial, nil, true, limit)
}

// Run performs the probe from the current process.
func Run(ctx context.Context) Result { return RunWith(ctx, nil, nil) }

// Dial opens a connection on some route (net.Dialer.DialContext style).
type Dial func(ctx context.Context, network, addr string) (net.Conn, error)

// RunWith performs the probe with dial (nil: this process's own route) and
// resolver (nil: the system's) - for engines that make every connection
// themselves (internal/splitstack).
func RunWith(ctx context.Context, dial Dial, resolver *net.Resolver) Result {
	return RunWithTimeout(ctx, dial, resolver, 8*time.Second)
}

// RunWithTimeout is RunWith with its own limit per request (routes with
// slow first connections, such as a fresh Tor, need more than 8 s).
func RunWithTimeout(ctx context.Context, dial Dial, resolver *net.Resolver, limit time.Duration) Result {
	return run(ctx, dial, resolver, false, limit)
}

func run(ctx context.Context, dial Dial, resolver *net.Resolver, tor bool, limit time.Duration) Result {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	var r Result
	r.Tor = tor
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		c := &http.Client{Timeout: limit}
		if dial != nil {
			c.Transport = &http.Transport{DialContext: dial, Proxy: nil, TLSHandshakeTimeout: limit}
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, IPURL, nil)
		resp, err := c.Do(req)
		if err != nil {
			r.IPErr = short(err)
			return
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 100))
		if ip := net.ParseIP(strings.TrimSpace(string(b))); ip != nil {
			r.IP = ip.String()
		} else {
			r.IPErr = "unexpected answer"
		}
	}()
	go func() {
		defer wg.Done()
		if tor {
			r.IsTor, r.TorErr = isTor(ctx, dial)
			return
		}
		dctx, cancel := context.WithTimeout(ctx, limit)
		defer cancel()
		txt, err := resolver.LookupTXT(dctx, DNSName)
		if err != nil {
			r.DNSErr = short(err)
			return
		}
		for _, t := range txt {
			if net.ParseIP(t) != nil {
				r.Resolver = t
				break
			}
		}
	}()
	wg.Wait()
	return r
}

// isTor asks check.torproject.org whether the request came out of Tor.
func isTor(ctx context.Context, dial Dial) (bool, string) {
	c := &http.Client{Timeout: 8 * time.Second}
	if dial != nil {
		c.Transport = &http.Transport{DialContext: dial, Proxy: nil, TLSHandshakeTimeout: 8 * time.Second}
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, TorURL, nil)
	resp, err := c.Do(req)
	if err != nil {
		return false, short(err)
	}
	defer resp.Body.Close()
	var v struct{ IsTor bool }
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&v); err != nil {
		return false, "unexpected answer"
	}
	return v.IsTor, ""
}

func short(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i > 0 && len(s) > 80 {
		s = s[i+2:]
	}
	return s
}

// RouteResult is the probe result for one route plus a verdict.
type RouteResult struct {
	Route   string `json:"route"`
	Result  Result `json:"result"`
	Verdict string `json:"verdict"` // ok | leak | blocked | error | warn
	Note    string `json:"note,omitempty"`
	// Verdict "starting" (Tor not through the network yet): Progress is its percent
	Progress int `json:"progress,omitempty"`
	// Detail: the reason behind the note (untranslated), e.g. the last line of a tor that died
	Detail string `json:"detail,omitempty"`
}

// Runner runs the probe inside route and returns its JSON Result.
type Runner func(ctx context.Context, route string) ([]byte, error)

// LeakTest runs a probe in every route.
func LeakTest(ctx context.Context, run Runner, routes []string) []RouteResult {
	out := make([]RouteResult, len(routes))
	var wg sync.WaitGroup
	for i, route := range routes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out[i] = RouteResult{Route: route}
			b, err := run(ctx, route)
			if err != nil {
				out[i].Verdict, out[i].Note = "error", fmt.Sprintf("probe failed: %v", err)
				return
			}
			if err := json.Unmarshal(b, &out[i].Result); err != nil {
				out[i].Verdict, out[i].Note = "error", "bad probe output"
			}
		}()
	}
	wg.Wait()
	judge(out)
	return out
}

// judge compares every route against the direct route.
func judge(rs []RouteResult) {
	var direct *Result
	for i := range rs {
		if rs[i].Route == "direct" {
			direct = &rs[i].Result
		}
	}
	for i := range rs {
		r := &rs[i]
		if r.Verdict == "error" {
			continue
		}
		res := r.Result
		switch {
		case r.Route == "block":
			if res.IP != "" || res.Resolver != "" {
				r.Verdict, r.Note = "leak", "block route reached the internet"
			} else {
				r.Verdict, r.Note = "blocked", "nothing gets out, as it should"
			}
		case r.Route == "direct":
			r.Verdict = "ok"
			if res.IP == "" {
				r.Verdict, r.Note = "error", "no internet on the direct route"
			}
		case strings.HasPrefix(r.Route, "link:"):
			// no tunnel: the public IP of that connection is the point
			switch {
			case res.IP == "" && res.Resolver == "":
				r.Verdict, r.Note = "blocked", "not connected: blocked instead of using another connection"
			case res.IP == "":
				r.Verdict, r.Note = "warn", "partly working: "+strings.TrimSpace(res.IPErr+" "+res.DNSErr)
			default:
				r.Verdict, r.Note = "ok", "no tunnel: this connection's own address"
			}
		case res.Tor:
			r.Verdict, r.Note = judgeTor(res, direct)
			if r.Verdict == "blocked" && r.Detail == "" {
				r.Detail = res.IPErr // why: the cause is visible right away
			}
		case res.IP == "" && res.Resolver == "":
			r.Verdict, r.Note = "blocked", "no internet through this tunnel (it may still be up, e.g. one that only reaches a home network) - nothing leaked"
		case direct != nil && direct.IP != "" && res.IP == direct.IP:
			r.Verdict, r.Note = "leak", "same public IP as the direct route"
		case direct != nil && direct.Resolver != "" && res.Resolver == direct.Resolver:
			r.Verdict, r.Note = "warn", "same DNS resolver as the direct route"
		case res.IP == "" || res.Resolver == "":
			r.Verdict, r.Note = "warn", "partly working: "+strings.TrimSpace(res.IPErr+" "+res.DNSErr)
		default:
			r.Verdict = "ok"
		}
	}
}

// judgeTor: Tor resolves names itself and its DNS port does not answer
// the resolver query, so "DNS seen as -" is normal here; what counts is that
// the public IP differs from the direct one and check.torproject.org agrees.
func judgeTor(res Result, direct *Result) (verdict, note string) {
	switch {
	case res.IP == "" && !res.IsTor:
		return "blocked", "no internet through this tunnel (it may still be up, e.g. one that only reaches a home network) - nothing leaked"
	case direct != nil && direct.IP != "" && res.IP == direct.IP:
		return "leak", "same public IP as the direct route"
	case res.IsTor:
		return "ok", "Tor confirmed (check.torproject.org); names are resolved inside Tor, so no resolver is shown"
	case res.TorErr != "":
		return "ok", "Tor: names are resolved inside Tor, so no resolver is shown; the Tor check could not be reached"
	default:
		return "warn", "the exit is not recognised as a Tor exit by check.torproject.org"
	}
}
