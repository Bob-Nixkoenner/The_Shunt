// Package api defines the JSON-over-Unix-socket API between shuntd and its
// frontends (CLI now, GUIs later). Plain HTTP+JSON keeps every frontend
// technology (Go, Tauri, Flutter, curl) a first-class citizen.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/tunnel"
)

// Status is returned by GET /v1/status.
type Status struct {
	DefaultRoute string         `json:"default_route"`
	Panic        bool           `json:"panic"`
	Tunnels      []TunnelStatus `json:"tunnels"`
	Groups       []GroupStatus  `json:"groups"`
	Rules        []string       `json:"rules"`
	// Routes lists every route name ("direct", "block", "tunnel:vps").
	Routes []string `json:"routes"`
	// DNS lists the upstreams per route ("direct", "tunnel:vps").
	DNS      map[string][]string `json:"dns,omitempty"`
	Warnings []string            `json:"warnings,omitempty"`
}

// TunnelStatus describes one tunnel.
type TunnelStatus struct {
	Name   string              `json:"name"`
	Iface  string              `json:"iface"`
	Driver string              `json:"driver"`
	Up     bool                `json:"up"`
	Error  string              `json:"error,omitempty"`
	Peers  []tunnel.PeerStatus `json:"peers,omitempty"`
}

// GroupStatus describes one process group.
type GroupStatus struct {
	Name  string `json:"name"`
	Procs int    `json:"procs"`
	// Route the group's processes take (first rule using the group).
	Route string `json:"route,omitempty"`
	// Apps lists the distinct program names in the group.
	Apps []string `json:"apps,omitempty"`
}

// RunRequest asks shuntd to move the calling process into a group. The
// daemon takes the PID from the socket credentials, never from the request.
type RunRequest struct {
	Group string `json:"group"`
}

// PanicRequest switches the panic mode.
type PanicRequest struct {
	On bool `json:"on"`
}

// Error is the body of every non-2xx response.
type Error struct {
	Error string `json:"error"`
}

// Client talks to shuntd.
type Client struct {
	http *http.Client
}

// NewClient returns a client for the given socket path.
func NewClient(socket string) *Client {
	return &Client{http: &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socket)
			},
			// The PID is read from the connection, so it must be ours.
			DisableKeepAlives: true,
		},
	}}
}

// Do performs a request; in and out may be nil.
func (c *Client) Do(method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, "http://shuntd"+path, body)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		var e Error
		_ = json.NewDecoder(resp.Body).Decode(&e)
		return fmt.Errorf("shuntd: %s", e.Error)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}
