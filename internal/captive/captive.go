// Package captive detects Wi-Fi login pages (hotel, train, company guest
// Wi-Fi): until you log in there, no VPN can connect.
//
// It fetches a plain-HTTP page with known content, the way NetworkManager,
// Firefox and Android do. The request goes out directly (shuntd's own
// traffic is not classified); it tells the probe host (GNOME's, which
// NetworkManager on most distributions asks anyway) that you are online.
// daemon.captive_check = false turns it off.
package captive

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// States.
const (
	Online  = "online"
	Portal  = "portal"  // a login page intercepts traffic
	Offline = "offline" // no answer at all
)

// DefaultURL answers "NetworkManager is online\n" when nothing is in the way.
const DefaultURL = "http://nmcheck.gnome.org/check_network_status.txt"

const expect = "NetworkManager is online"

// URL returns the probe URL (SHUNT_CAPTIVE_URL overrides it, for tests).
func URL() string {
	if u := os.Getenv("SHUNT_CAPTIVE_URL"); u != "" {
		return u
	}
	return DefaultURL
}

// Probe checks once. For Portal it returns the login page if the portal
// gave one (redirect target), else the probe URL itself.
func Probe(ctx context.Context, url string) (state, login string) {
	cl := &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			Proxy:       nil, // the portal is in front of any proxy
			DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			// no "Accept-Encoding: gzip": NetworkManager does not send it
			DisableCompression: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return Offline, ""
	}
	// The same request as NetworkManager's own check (libcurl defaults:
	// no User-Agent, "Accept: */*", "Connection: close"), so the network
	// cannot tell The Shunt from any other Linux machine.
	req.Header.Set("User-Agent", "")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Connection", "close")
	resp, err := cl.Do(req)
	if err != nil {
		return Offline, ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode == http.StatusOK && strings.HasPrefix(string(body), expect) {
		return Online, ""
	}
	if loc := resp.Header.Get("Location"); resp.StatusCode/100 == 3 && strings.HasPrefix(loc, "http") {
		return Portal, loc
	}
	return Portal, url
}
