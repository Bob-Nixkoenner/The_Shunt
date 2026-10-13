// Package probe implements the leak self-test: for every route a probe
// process is started inside that route and reports which public IP and
// which DNS resolver the outside world sees.
//
// The probe contacts two third parties: api.ipify.org (public IP) and
// Google's o-o.myaddr.l.google.com (which resolver asked). Callers must
// make that clear to the user before running it.
package probe

import (
	"github.com/Bob-Nixkoenner/the_shunt/internal/api"

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
}

// Run performs the probe from the current process.
func Run(ctx context.Context) Result {
	var r Result
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		c := &http.Client{Timeout: 8 * time.Second}
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
		dctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
		txt, err := net.DefaultResolver.LookupTXT(dctx, DNSName)
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
}

// Runner runs the probe inside route and returns its JSON Result.
type Runner func(ctx context.Context, route string) ([]byte, error)

// DaemonRunner lets shuntd start the probe right inside the route: no
// `shunt run`, so no password for leaving the caller's own route.
func DaemonRunner(c *api.Client) Runner {
	return func(_ context.Context, route string) ([]byte, error) {
		var raw json.RawMessage
		err := c.Do("POST", "/v1/probe", api.ProbeRequest{Route: route}, &raw)
		return raw, err
	}
}

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
		case res.IP == "" && res.Resolver == "" && strings.HasPrefix(r.Route, "link:"):
			r.Verdict, r.Note = "blocked", "not connected: blocked instead of using another connection"
		case res.IP == "" && res.Resolver == "":
			r.Verdict, r.Note = "blocked", "tunnel not usable: blocked instead of leaking"
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
