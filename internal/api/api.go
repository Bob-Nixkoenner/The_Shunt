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

	"github.com/Bob-Nixkoenner/the_shunt/internal/blocklist"
	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/Bob-Nixkoenner/the_shunt/internal/dnsproxy"
	"github.com/Bob-Nixkoenner/the_shunt/internal/health"
	"github.com/Bob-Nixkoenner/the_shunt/internal/netdetect"
	"github.com/Bob-Nixkoenner/the_shunt/internal/sockets"
	"github.com/Bob-Nixkoenner/the_shunt/internal/speedtest"
	"github.com/Bob-Nixkoenner/the_shunt/internal/stats"
	"github.com/Bob-Nixkoenner/the_shunt/internal/tunnel"
)

// Status is returned by GET /v1/status.
type Status struct {
	// Traffic: totals per tunnel and "total" (this month, last month, all).
	Traffic      map[string]stats.Summary `json:"traffic,omitempty"`
	DefaultRoute string                   `json:"default_route"`
	Panic        bool                     `json:"panic"`
	PassLeft     int64                    `json:"pass_left,omitempty"`  // seconds of a running pass
	TorAll       string                   `json:"tor_all,omitempty"`    // tunnel everything goes through (tor-all)
	PanicKill    bool                     `json:"panic_kill,omitempty"` // panic also ends tunnel apps (daemon.panic_kill)
	Tunnels      []TunnelStatus           `json:"tunnels"`
	Groups       []GroupStatus            `json:"groups"`
	Rules        []string                 `json:"rules"`
	// Routes lists every route name ("direct", "block", "tunnel:vps").
	Routes []string `json:"routes"`
	// DNS lists the upstreams per route ("direct", "tunnel:vps").
	DNS      map[string][]string `json:"dns,omitempty"`
	Warnings []string            `json:"warnings,omitempty"`
	// Network is the matched [[network]] profile ("" = none), NetInfo what
	// the machine is connected to right now.
	Network string `json:"network,omitempty"`
	// Captive: "portal" when a Wi-Fi login page is in the way (tunnels
	// can't connect until you log in), "online", "offline" or "" (unknown,
	// check off). CaptiveURL is the login page.
	Captive    string `json:"captive,omitempty"`
	CaptiveURL string `json:"captive_url,omitempty"`
	// Firewall is the app firewall mode in effect (off | ask | block),
	// Pending the number of programs waiting for a decision.
	Firewall string `json:"firewall,omitempty"`
	// Platform of the daemon ("" = Linux); the web UI hides what only
	// exists there.
	Platform string `json:"platform,omitempty"`
	// Version of the running shuntd (the installed one after an update).
	Version string `json:"version,omitempty"`
	Pending int    `json:"pending,omitempty"`
	// DNSFailing: routes whose DNS servers don't answer (route -> last error).
	DNSFailing map[string]string `json:"dns_failing,omitempty"`
	NetInfo    netdetect.Info    `json:"net_info"`
	// DNSFilter: blocklist levels in effect, lists and counters.
	DNSFilter *DNSFilterStatus `json:"dns_filter,omitempty"`
	// Inbound: the protection against incoming connections in effect
	// (closed | lan | open, "" = off); InboundAsk is set while an unknown
	// network waits for a decision.
	Inbound    string      `json:"inbound,omitempty"`
	InboundAsk *InboundAsk `json:"inbound_ask,omitempty"`
}

// DNSFilterStatus describes the DNS filter.
type DNSFilterStatus struct {
	Default string `json:"default"`
	// Routes: the level per route right now ("direct" -> "paranoid"),
	// Rules: the rules with their own level (rule name -> level).
	Routes map[string]string    `json:"routes"`
	Rules  map[string]string    `json:"rules,omitempty"`
	Lists  []blocklist.Status   `json:"lists"`
	Stats  dnsproxy.FilterStats `json:"stats"`
}

// TunnelStatus describes one tunnel.
type TunnelStatus struct {
	Name   string `json:"name"`
	Iface  string `json:"iface"`
	Driver string `json:"driver"`
	Up     bool   `json:"up"`
	// Disabled: switched off in the config (its route blocks).
	Disabled bool   `json:"disabled,omitempty"`
	Error    string `json:"error,omitempty"`
	Via      string `json:"via,omitempty"` // second hop through this route
	// Bootstrap: tor tunnels only, 0..100 (100 = connected).
	Bootstrap *int                `json:"bootstrap,omitempty"`
	Socks     string              `json:"socks,omitempty"` // loopback address of its SOCKS5 exit
	Peers     []tunnel.PeerStatus `json:"peers,omitempty"`
	Health    *health.Report      `json:"health,omitempty"` // nil until the first check
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
	// Windows: the process (started suspended by the caller) and its route.
	// shuntd on Linux ignores them.
	PID   int    `json:"pid,omitempty"`
	Route string `json:"route,omitempty"`
}

// AdoptRequest asks shuntd to move processes of the caller's own user into a
// group, after they started: snap-confined apps need a cgroup of their own
// while they start and can only be moved once they have exec'd. Only
// processes of the caller's uid that run in no route yet are accepted.
type AdoptRequest struct {
	Group string `json:"group"`
	PIDs  []int  `json:"pids"`
}

// ProbeRequest asks the daemon to run the leak test probe in a route
// (POST /v1/probe, answer: probe.Result).
type ProbeRequest struct {
	Route string `json:"route"`
}

// SpeedStepRequest asks the daemon to run one speed measurement inside a route
// (POST /v1/speedtest/step, answer: speedtest.Measurement).
type SpeedStepRequest struct {
	Route string         `json:"route"`
	Step  speedtest.Step `json:"step"`
}

// ConfigView is returned by GET /v1/config. Private keys are never included.
type ConfigView struct {
	Raw string `json:"raw"`
	// Version identifies the file content; send it back with a save so a
	// change made meanwhile (editor, another window) is not overwritten.
	Version string           `json:"version"`
	Config  *config.Config   `json:"config"`
	Tunnels []TunnelConfInfo `json:"tunnels"`
	// DNSFilter: the filter settings in effect (defaults filled in, also
	// when the file has no [dns_filter]).
	DNSFilter config.DNSFilter `json:"dns_filter"`
}

// TunnelConfInfo is the public part of a tunnel's WireGuard or OpenVPN file.
type TunnelConfInfo struct {
	Name       string   `json:"name"`
	Type       string   `json:"type"` // wireguard | openvpn | tailscale | tor | tor
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
	// Driver "tailscale": Conf is a .ts file (login_server, auth_key, ...).
	Driver string `json:"driver,omitempty"`
}

// TorAllRequest is the body of POST /v1/torall.
type TorAllRequest struct {
	On     bool   `json:"on"`
	Tunnel string `json:"tunnel,omitempty"` // empty: the only Tor tunnel
}

// TunnelRename is the body of POST /v1/tunnels/{name}/rename.
type TunnelRename struct {
	To string `json:"to"`
}

// ProcRoute is a running process and the route its traffic takes
// (GET /v1/procs?name=...).
type ProcRoute struct {
	PID   int    `json:"pid"`
	Name  string `json:"name"`
	Route string `json:"route"`
	Group string `json:"group,omitempty"` // Shunt group, "" = none (default route)
}

// FirewallDecision is the body of POST /v1/pending/{id}: the route for a
// waiting program ("" = the default route) and whether to keep it.
type FirewallDecision struct {
	Route    string `json:"route"`
	Remember bool   `json:"remember"`
}

// PanicRequest switches the panic mode.
type PanicRequest struct {
	On bool `json:"on"`
}

// PassRequest lets everything through (direct) for Minutes (1..60, see
// internal/override); 0 ends a pass.
type PassRequest struct {
	Minutes int `json:"minutes"`
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
					return nil, fmt.Errorf("no access to %s: restart the computer (new 'shunt' group membership; logging out is not always enough), or use sudo", socket)
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
	return c.DoCtx(context.Background(), method, path, in, out)
}

// DoCtx is Do with a context (cancel a long request).
func (c *Client) DoCtx(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://shuntd"+path, body)
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

// Probe lets shuntd start the leak-test probe right inside route (no
// `shunt run`, so no password for leaving the caller's own route); it fits
// probe.Runner.
func (c *Client) Probe(_ context.Context, route string) ([]byte, error) {
	var raw json.RawMessage
	err := c.Do("POST", "/v1/probe", ProbeRequest{Route: route}, &raw)
	return raw, err
}

// SpeedStep runs one speed measurement in route; it fits speedtest.Runner.
func (c *Client) SpeedStep(ctx context.Context, route string, s speedtest.Step) (speedtest.Measurement, error) {
	var m speedtest.Measurement
	err := c.DoCtx(ctx, "POST", "/v1/speedtest/step", SpeedStepRequest{Route: route, Step: s}, &m)
	return m, err
}

// Listening answers GET /v1/listening: what on this machine waits for
// connections from outside, and from where it can be reached.
type Listening struct {
	// Network: the matched [[network]] profile, "" = an unknown network.
	Network string `json:"network,omitempty"`
	// Uplinks: the connected physical links (Wi-Fi, cable, mobile);
	// Tunnels: the tunnel interfaces.
	Uplinks []string   `json:"uplinks,omitempty"`
	Tunnels []string   `json:"tunnels,omitempty"`
	Ports   []OpenPort `json:"ports"`
	// Firewalls: other packet filters that are active (ufw, firewalld,
	// other nftables tables). They may block some of these ports already.
	Firewalls []string `json:"firewalls,omitempty"`
	// Inbound: the mode in effect (closed | lan | open, "" = The Shunt
	// does not filter incoming connections).
	Inbound string `json:"inbound,omitempty"`
	Error   string `json:"error,omitempty"`
}

// OpenPort is one listening socket.
type OpenPort struct {
	Proto string `json:"proto"` // tcp | udp
	Addr  string `json:"addr"`  // the address it is bound to
	Port  uint16 `json:"port"`
	// Reach: "localhost" (only this machine), "all" (every interface) or
	// "iface" (the interfaces in Ifaces).
	Reach  string   `json:"reach"`
	Ifaces []string `json:"ifaces,omitempty"`
	// Exposed: reachable from the network you are connected to;
	// Tunnel: reachable from the other side of a tunnel.
	Exposed bool `json:"exposed"`
	Tunnel  bool `json:"tunnel"`
	// Blocked: The Shunt drops new connections to it from the network
	// (LANOnly: only private addresses get through).
	Blocked bool          `json:"blocked,omitempty"`
	LANOnly bool          `json:"lan_only,omitempty"`
	Owner   sockets.Owner `json:"owner"`
	UID     uint32        `json:"uid"`
	V6Only  bool          `json:"v6only,omitempty"`
}

// InboundAsk: on a network without a profile, incoming connections are
// blocked and the user is asked whether to trust it.
type InboundAsk struct {
	SSID       string `json:"ssid,omitempty"`
	GatewayMAC string `json:"gateway_mac,omitempty"`
}

// InboundDecision answers an InboundAsk (POST /v1/inbound/network):
// "home" adds a [[network]] profile for it with inbound = "lan",
// "closed" keeps it closed and stops asking.
type InboundDecision struct {
	SSID       string `json:"ssid,omitempty"`
	GatewayMAC string `json:"gateway_mac,omitempty"`
	Action     string `json:"action"`
	// Name of the new profile ("" = from the SSID).
	Name string `json:"name,omitempty"`
}
