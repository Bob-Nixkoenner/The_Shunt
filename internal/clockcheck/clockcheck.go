// Package clockcheck compares the system clock with the time web servers
// report (the Date header), asked through the tunnel: the idea of Tails'
// htpdate/Whonix' sdwdate. A clock that is minutes off breaks WireGuard
// handshakes of some setups and every TLS certificate check, and it is a
// fingerprint too. Nothing is ever set: shuntd only warns.
package clockcheck

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"time"
)

// Sites asked by default (HTTPS, any answer carries a Date header).
var Sites = []string{"https://www.cloudflare.com/", "https://www.wikipedia.org/"}

// Offset asks url and returns server time minus local time. The local time
// is taken half a round trip after the request left.
func Offset(ctx context.Context, c *http.Client, url string) (time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return 0, err
	}
	t0 := time.Now()
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	rtt := time.Since(t0)
	d, err := http.ParseTime(resp.Header.Get("Date"))
	if err != nil {
		return 0, errors.New("no usable Date header from " + url)
	}
	// Date has a resolution of one second: the server's second began up to 1 s ago
	return d.Add(500 * time.Millisecond).Sub(t0.Add(rtt / 2)), nil
}

// Median asks all urls and returns the median offset; an error when none answered.
func Median(ctx context.Context, c *http.Client, urls []string) (time.Duration, error) {
	var offs []time.Duration
	var last error
	for _, u := range urls {
		o, err := Offset(ctx, c, u)
		if err != nil {
			last = err
			continue
		}
		offs = append(offs, o)
	}
	if len(offs) == 0 {
		if last == nil {
			last = errors.New("no site")
		}
		return 0, last
	}
	sort.Slice(offs, func(i, j int) bool { return offs[i] < offs[j] })
	return offs[len(offs)/2], nil
}

// Skewed: more than limit off in either direction.
func Skewed(off, limit time.Duration) bool { return off > limit || off < -limit }
