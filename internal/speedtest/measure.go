// Package speedtest measures how fast a route is: latency, download and
// upload against a public speed-test server (Cloudflare by default), run from
// a process that sits in the route, so the traffic takes exactly that route.
// The orchestration (random order, several rounds, median) is in run.go.
package speedtest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// Providers and measurement kinds. Only these are accepted from callers.
const (
	Cloudflare = "cloudflare"
	NDT7       = "ndt7"

	KindPing = "ping"
	KindDown = "down"
	KindUp   = "up"
)

// BaseURL is the Cloudflare speed test server. SHUNT_SPEEDTEST_URL overrides
// it (used by tests, never set by the service).
var BaseURL = "https://speed.cloudflare.com"

func init() {
	if u := os.Getenv("SHUNT_SPEEDTEST_URL"); u != "" {
		BaseURL = strings.TrimRight(u, "/")
	}
}

// Limits for the sizes callers may ask for.
const (
	MaxBytes     = 100_000_000
	DefaultBytes = 25_000_000
	MaxPings     = 30
)

// Measurement is what one step saw. Zero fields were not measured.
type Measurement struct {
	LatencyMs float64 `json:"latency_ms,omitempty"` // median round trip
	JitterMs  float64 `json:"jitter_ms,omitempty"`  // mean difference between neighbours
	Mbit      float64 `json:"mbit,omitempty"`       // download or upload speed
	Bytes     int64   `json:"bytes,omitempty"`      // moved for Mbit
	IP        string  `json:"ip,omitempty"`         // public IP seen by the server
	Loc       string  `json:"loc,omitempty"`        // its country
	Err       string  `json:"error,omitempty"`
}

// Step is one thing to measure.
type Step struct {
	Provider string `json:"provider"`
	Kind     string `json:"kind"`
	Bytes    int64  `json:"bytes,omitempty"` // down/up: how much to move
}

// Validate checks a step that came from outside.
func (s *Step) Validate() error {
	switch s.Provider {
	case Cloudflare, NDT7:
	default:
		return fmt.Errorf("unknown provider %q", s.Provider)
	}
	switch s.Kind {
	case KindPing:
		s.Bytes = 0
	case KindDown, KindUp:
		if s.Bytes == 0 {
			s.Bytes = DefaultBytes
		}
		if s.Bytes < 100_000 || s.Bytes > MaxBytes {
			return fmt.Errorf("bytes must be 100000 to %d", MaxBytes)
		}
	default:
		return fmt.Errorf("unknown kind %q", s.Kind)
	}
	return nil
}

// Measure runs a step from this process. The server speaks HTTPS; a
// context deadline bounds it.
func Measure(ctx context.Context, s Step) Measurement {
	if err := s.Validate(); err != nil {
		return Measurement{Err: err.Error()}
	}
	switch s.Provider {
	case NDT7:
		return measureNDT7(ctx, s)
	}
	m := measureCloudflare(ctx, s)
	if m.Err != "" {
		m.Err = short(m.Err)
	}
	return m
}

func client() *http.Client {
	return &http.Client{Transport: &http.Transport{
		Proxy:               nil,
		TLSHandshakeTimeout: 10 * time.Second,
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		DisableCompression:  true,
		MaxIdleConns:        2,
	}}
}

func measureCloudflare(ctx context.Context, s Step) Measurement {
	c := client()
	defer c.CloseIdleConnections()
	var m Measurement
	switch s.Kind {
	case KindPing:
		lat, err := pings(ctx, c, 10)
		if err != nil {
			m.Err = err.Error()
			return m
		}
		m.LatencyMs, m.JitterMs = median(lat), jitter(lat)
	case KindDown:
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/__down?bytes=%d", BaseURL, s.Bytes), nil)
		resp, err := c.Do(req)
		if err != nil {
			m.Err = err.Error()
			return m
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			m.Err = fmt.Sprintf("server answered %d", resp.StatusCode)
			return m
		}
		first := make([]byte, 1)
		if _, err := io.ReadFull(resp.Body, first); err != nil {
			m.Err = err.Error()
			return m
		}
		t0 := time.Now() // from the first byte: connection setup is not speed
		n, err := io.Copy(io.Discard, resp.Body)
		n++
		if err != nil && !errors.Is(err, context.DeadlineExceeded) {
			m.Err = err.Error()
			return m
		}
		m.Bytes, m.Mbit = n, mbit(n-1, time.Since(t0))
	case KindUp:
		body := &zeros{n: s.Bytes}
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, BaseURL+"/__up", body)
		req.ContentLength = s.Bytes
		req.Header.Set("Content-Type", "application/octet-stream")
		t0 := time.Now()
		resp, err := c.Do(req)
		if err != nil {
			m.Err = err.Error()
			return m
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			m.Err = fmt.Sprintf("server answered %d", resp.StatusCode)
			return m
		}
		m.Bytes, m.Mbit = s.Bytes, mbit(s.Bytes, time.Since(t0))
	}
	// where the server sees us: shows the route really was taken
	if ip, loc := trace(ctx, c); ip != "" {
		m.IP, m.Loc = ip, loc
	}
	return m
}

// pings: n round trips of an empty download on one connection (the first,
// which includes the connection setup, is dropped).
func pings(ctx context.Context, c *http.Client, n int) ([]float64, error) {
	if n > MaxPings {
		n = MaxPings
	}
	var out []float64
	for i := 0; i <= n; i++ {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, BaseURL+"/__down?bytes=0", nil)
		t0 := time.Now()
		resp, err := c.Do(req)
		if err != nil {
			return nil, err
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("server answered %d", resp.StatusCode)
		}
		if i > 0 {
			out = append(out, float64(time.Since(t0).Microseconds())/1000)
		}
	}
	return out, nil
}

func trace(ctx context.Context, c *http.Client) (ip, loc string) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, BaseURL+"/cdn-cgi/trace", nil)
	resp, err := c.Do(req)
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	for _, l := range strings.Split(string(b), "\n") {
		switch {
		case strings.HasPrefix(l, "ip="):
			ip = strings.TrimSpace(l[3:])
		case strings.HasPrefix(l, "loc="):
			loc = strings.TrimSpace(l[4:])
		}
	}
	if net.ParseIP(ip) == nil {
		return "", ""
	}
	return ip, loc
}

func mbit(bytes int64, d time.Duration) float64 {
	if d <= 0 || bytes <= 0 {
		return 0
	}
	return float64(bytes) * 8 / 1e6 / d.Seconds()
}

func median(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	if len(s)%2 == 1 {
		return s[len(s)/2]
	}
	return (s[len(s)/2-1] + s[len(s)/2]) / 2
}

func jitter(v []float64) float64 {
	if len(v) < 2 {
		return 0
	}
	var sum float64
	for i := 1; i < len(v); i++ {
		d := v[i] - v[i-1]
		if d < 0 {
			d = -d
		}
		sum += d
	}
	return sum / float64(len(v)-1)
}

type zeros struct{ n int64 }

func (z *zeros) Read(p []byte) (int, error) {
	if z.n <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > z.n {
		p = p[:z.n]
	}
	clear(p)
	z.n -= int64(len(p))
	return len(p), nil
}

func short(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if i := strings.LastIndex(s, ": "); i >= 0 && len(s) > 80 {
		s = s[i+2:]
	}
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}
