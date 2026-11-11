package defense

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"
)

// The outside check: a server of your own (tools/outside-scan.sh) connects
// back to the address the request came from and reports which fixed ports
// answer. The client never names a target and never sends a port list, so
// the server cannot be used to scan anything else; the client in turn
// refuses an answer about an address that is not one of this machine's own
// public addresses.

// MaxOutsidePorts caps the number of ports an answer may list.
const MaxOutsidePorts = 100

// OutsideTimeout is how long one check may take in total.
const OutsideTimeout = 90 * time.Second

// OutsideCheck is the answer for one address family.
type OutsideCheck struct {
	Family string `json:"family"` // "v4" | "v6"
	Open   []int  `json:"open"`
	// Scanned is how many ports the server tried (as it reported).
	Scanned int    `json:"scanned,omitempty"`
	Error   string `json:"error,omitempty"`
}

// OutsideResult is what the check found; Status carries the last one.
type OutsideResult struct {
	Time   time.Time      `json:"time"`
	Checks []OutsideCheck `json:"checks"`
}

// OpenCount is the number of open ports over all families.
func (r OutsideResult) OpenCount() int {
	n := 0
	for _, c := range r.Checks {
		n += len(c.Open)
	}
	return n
}

// ValidateOutsideScan checks the [defense.outside_scan] section.
func ValidateOutsideScan(c OutsideScanConfig) error {
	if c.Host == "" {
		if c.Enabled {
			return errors.New("defense.outside_scan.host: needed while enabled")
		}
		return nil
	}
	u, err := url.Parse(c.Host)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("defense.outside_scan.host %q: use an http:// or https:// URL without credentials", c.Host)
	}
	if len(c.Host) > 300 || len(c.Token) > 200 || strings.ContainsAny(c.Token, "\r\n") {
		return errors.New("defense.outside_scan: host or token too long, or token with a line break")
	}
	return nil
}

// OutsideScan asks the configured server which ports answer from the
// internet. clientFor returns an HTTP client that reaches the server over
// the given network ("tcp4" or "tcp6") outside any tunnel; own says whether
// an address belongs to this machine. Families without a public address
// (per e) are not asked.
func OutsideScan(ctx context.Context, cfg OutsideScanConfig, e Exposure, clientFor func(network string) *http.Client, own func(netip.Addr) bool) (OutsideResult, error) {
	res := OutsideResult{Time: time.Now(), Checks: []OutsideCheck{}}
	if !cfg.Enabled {
		return res, errors.New("the outside check is off")
	}
	if err := ValidateOutsideScan(cfg); err != nil {
		return res, err
	}
	if !e.Any() {
		return res, errors.New("this device has no public address, nothing to check from outside")
	}
	ctx, cancel := context.WithTimeout(ctx, OutsideTimeout)
	defer cancel()
	for _, f := range []struct {
		on      bool
		fam, nw string
	}{{e.V4, "v4", "tcp4"}, {e.V6, "v6", "tcp6"}} {
		if !f.on {
			continue
		}
		c := OutsideCheck{Family: f.fam, Open: []int{}}
		got, scanned, err := askOutside(ctx, cfg, clientFor(f.nw), f.fam, own)
		if err != nil {
			c.Error = err.Error()
		} else {
			c.Open, c.Scanned = got, scanned
		}
		res.Checks = append(res.Checks, c)
	}
	return res, nil
}

func askOutside(ctx context.Context, cfg OutsideScanConfig, hc *http.Client, fam string, own func(netip.Addr) bool) ([]int, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.Host, strings.NewReader("{}"))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if cfg.Token != "" {
		req.Header.Set("X-Shunt-Token", cfg.Token)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("server not reachable: %w", errors.Unwrap(err))
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, 0, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("server answered %d", resp.StatusCode)
	}
	var r struct {
		Addr    string `json:"addr"`
		Open    []int  `json:"open"`
		Scanned int    `json:"scanned"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, 0, errors.New("the server's answer is not valid")
	}
	if r.Error != "" {
		return nil, 0, fmt.Errorf("server: %.100s", r.Error)
	}
	a, err := netip.ParseAddr(r.Addr)
	if err != nil {
		return nil, 0, errors.New("the server's answer names no address")
	}
	a = a.Unmap()
	if (fam == "v4") != a.Is4() {
		return nil, 0, errors.New("the server checked another address family")
	}
	if own == nil || !own(a) {
		return nil, 0, errors.New("the server checked an address that is not yours; answer refused")
	}
	if len(r.Open) > MaxOutsidePorts {
		return nil, 0, errors.New("the server's answer lists too many ports")
	}
	seen := map[int]bool{}
	out := []int{}
	for _, p := range r.Open {
		if p < 1 || p > 65535 {
			return nil, 0, errors.New("the server's answer holds an invalid port")
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Ints(out)
	return out, r.Scanned, nil
}
