// Package api defines the JSON-over-Unix-socket API between shuntd and its
// frontends (CLI now, GUIs later). Plain HTTP+JSON keeps every frontend
// technology (Go, Tauri, Flutter, curl) a first-class citizen.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"syscall"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/Bob-Nixkoenner/the_shunt/internal/netdetect"
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
	// Network is the matched [[network]] profile ("" = none), NetInfo what
	// the machine is connected to right now.
	Network string `json:"network,omitempty"`
	// DNSFailing: routes whose DNS servers don't answer (route -> last error).
	DNSFailing map[string]string `json:"dns_failing,omitempty"`
	NetInfo    netdetect.Info    `json:"net_info"`
}

// TunnelStatus describes one tunnel.
type TunnelStatus struct {
	Name   string              `json:"name"`
	Iface  string              `json:"iface"`
	Driver string              `json:"driver"`
	Up     bool                `json:"up"`
	Error  string              `json:"error,omitempty"`
	Via    string              `json:"via,omitempty"` // second hop through this route
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

// ConfigView is returned by GET /v1/config. Private keys are never included.
type ConfigView struct {
	Raw string `json:"raw"`
	// Version identifies the file content; send it back with a save so a
	// change made meanwhile (editor, another window) is not overwritten.
	Version string           `json:"version"`
	Config  *config.Config   `json:"config"`
	Tunnels []TunnelConfInfo `json:"tunnels"`
}

// TunnelConfInfo is the public part of a tunnel's WireGuard or OpenVPN file.
type TunnelConfInfo struct {
	Name       string   `json:"name"`
	Type       string   `json:"type"` // wireguard | openvpn
	Endpoint   string   `json:"endpoint"`
	Addresses  []string `json:"addresses"`
	DNS        []string `json:"dns,omitempty"`
	AllowedIPs []string `json:"allowed_ips"`
}

// ConfigSave is the body of PUT /v1/config and POST /v1/config/check:
// either raw TOML or a structured config (comments are not kept).
type ConfigSave struct {
	Raw     string         `json:"raw,omitempty"`
	Config  *config.Config `json:"config,omitempty"`
	Version string         `json:"version,omitempty"` // from ConfigView; "" = don't check
}

// CheckResult reports whether a config would be accepted.
type CheckResult struct {
	OK       bool     `json:"ok"`
	Error    string   `json:"error,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

// TunnelImport is the body of POST /v1/tunnels.
type TunnelImport struct {
	Name string `json:"name"`
	Conf string `json:"conf"` // wg-quick file or .ovpn content
	DNS  string `json:"dns,omitempty"`
	// OpenVPN login, if the server wants one (auth-user-pass).
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	// Via: "tunnel:<name>" makes this a second hop.
	Via string `json:"via,omitempty"`
}

// ProcRoute is a running process and the route its traffic takes
// (GET /v1/procs?name=...).
type ProcRoute struct {
	PID   int    `json:"pid"`
	Name  string `json:"name"`
	Route string `json:"route"`
	Group string `json:"group,omitempty"` // Shunt group, "" = none (default route)
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
		// long enough for a polkit password dialog
		Timeout: 150 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				c, err := d.DialContext(ctx, "unix", socket)
				if errors.Is(err, syscall.EACCES) {
					return nil, fmt.Errorf("no access to %s: log out and in again (new 'shunt' group membership), or use sudo", socket)
				}
				return c, err
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
