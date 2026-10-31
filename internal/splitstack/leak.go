package splitstack

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/probe"
)

// routeNet returns how a route dials and resolves: names are looked up
// with the route's own DNS server, through that route (like the apps).
func (e *Engine) routeNet(route string) (probe.Dial, *net.Resolver, error) {
	var raw func(ctx context.Context, network string, ap netip.AddrPort) (net.Conn, error)
	var dnsSrv netip.Addr
	switch {
	case route == RouteBlock:
		return func(context.Context, string, string) (net.Conn, error) { return nil, errBlocked }, &net.Resolver{PreferGo: true,
			Dial: func(context.Context, string, string) (net.Conn, error) { return nil, errBlocked }}, nil
	case route == RouteDirect:
		dnsSrv = e.directDNS()
		raw = func(ctx context.Context, network string, ap netip.AddrPort) (net.Conn, error) {
			return e.o.DialDirect(ctx, network, ap.String())
		}
	case strings.HasPrefix(route, tunnelPref):
		t := e.wake(strings.TrimPrefix(route, tunnelPref))
		if t == nil || !t.reachable() {
			return nil, nil, fmt.Errorf("%s is not up", route)
		}
		dnsSrv = e.dnsServers(route)[0]
		raw = func(ctx context.Context, network string, ap netip.AddrPort) (net.Conn, error) {
			return t.dialAP(ctx, !strings.HasPrefix(network, "udp"), ap)
		}
	default:
		return nil, nil, fmt.Errorf("unknown route %q", route)
	}
	res := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return raw(ctx, network, netip.AddrPortFrom(dnsSrv, 53))
	}}
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		pn, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return nil, err
		}
		ip, err := netip.ParseAddr(host)
		if err != nil {
			ips, err := res.LookupNetIP(ctx, "ip4", host) // tunnels may lack IPv6
			if err != nil || len(ips) == 0 {
				return nil, fmt.Errorf("resolve %s: %v", host, err)
			}
			ip = ips[0]
		}
		return raw(ctx, network, netip.AddrPortFrom(ip.Unmap(), uint16(pn)))
	}
	return dial, res, nil
}

// LeakTest checks every route like `shunt leaktest`: which public IP and
// which DNS resolver the outside world sees (contacts api.ipify.org and
// Google's o-o.myaddr.l.google.com through each route). JSON list of
// probe.RouteResult; blocks for up to ~10 s.
func (e *Engine) LeakTest(ctx context.Context) string {
	routes := []string{RouteDirect, RouteBlock}
	var early []probe.RouteResult
	for _, t := range e.allTunnels() {
		if t = e.wake(t.name); t == nil {
			continue // a leak test is asked for: sleeping tunnels wake up
		}
		if t.isTor() && t.tor != nil {
			// Tor needs up to a minute from its start: wait for it instead of calling a Tor that is still starting "blocked"
			if n := t.tor.waitReady(ctx, torWaitMax); n < 100 {
				early = append(early, torNotReady(tunnelPref+t.name, t.tor, n))
				continue
			}
		}
		if t.reachable() {
			routes = append(routes, tunnelPref+t.name)
		}
	}
	res := probe.LeakTest(ctx, e.ProbeRoute, routes)
	b, _ := json.Marshal(append(res, early...))
	return string(b)
}

// torNotReady is the leak test row of a Tor that is not through the network:
// "starting" while it makes progress, "error" with the reason when it failed.
func torNotReady(route string, t *torTunnel, n int) probe.RouteResult {
	r := probe.RouteResult{Route: route, Verdict: "starting", Progress: n,
		Note: "Tor is still starting - run the test again in a moment"}
	if e := t.proc.Err(); e != "" {
		r.Verdict, r.Note, r.Detail = "error", "Tor does not start", e
	}
	return r
}

// torProbeLimit: the limit per request of the probe through Tor (a fresh Tor builds its first circuits slowly).
var torProbeLimit = 30 * time.Second

// ProbeRoute runs the leak-test probe through one route; the JSON is a
// probe.Result (it fits probe.Runner).
func (e *Engine) ProbeRoute(ctx context.Context, route string) ([]byte, error) {
	if t := e.tunnel(strings.TrimPrefix(route, tunnelPref)); strings.HasPrefix(route, tunnelPref) && t != nil && t.isTor() && t.tor != nil {
		if !t.reachable() {
			return nil, fmt.Errorf("%s is not up", route)
		}
		// like the apps (DialRoute): names go to Tor unresolved. Tor carries no
		// UDP, so a lookup through the tunnel's DNS server never answers and the
		// probe saw no IP ("blocked") although Tor worked. The first circuits of
		// a fresh Tor take their time.
		dial := func(ctx context.Context, _, addr string) (net.Conn, error) { return t.tor.dialName(ctx, addr) }
		return json.Marshal(probe.RunTorWith(ctx, dial, torProbeLimit))
	}
	dial, res, err := e.routeNet(route)
	if err != nil {
		return nil, err
	}
	return json.Marshal(probe.RunWith(ctx, dial, res))
}

// DialDefault dials the way an app without a rule goes (the default route
// of the network profile, names resolved through it): the service's own
// downloads (DNS filter lists) must not leave past the tunnel.
func (e *Engine) DialDefault(ctx context.Context, network, addr string) (net.Conn, error) {
	e.mu.RLock()
	route := e.def
	e.mu.RUnlock()
	dial, _, err := e.routeNet(route)
	if err != nil {
		return nil, err
	}
	return dial(ctx, network, addr)
}

// DialRoute dials addr (names allowed) through one route like an app on that
// route would: names are resolved by the route's own DNS. It serves the
// SOCKS5 exit of a tunnel ("socks = ..."): nothing leaves the tunnel.
func (e *Engine) DialRoute(ctx context.Context, route, network, addr string) (net.Conn, error) {
	if strings.HasPrefix(route, tunnelPref) {
		// Tor resolves names itself (and knows .onion): hand the name over
		if t := e.wake(strings.TrimPrefix(route, tunnelPref)); t != nil && t.isTor() && t.tor != nil && !strings.HasPrefix(network, "udp") {
			return t.tor.dialName(ctx, addr)
		}
	}
	dial, _, err := e.routeNet(route)
	if err != nil {
		return nil, err
	}
	return dial(ctx, network, addr)
}
