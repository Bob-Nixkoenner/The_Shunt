package splitstack

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

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
	for _, t := range e.allTunnels() {
		if t = e.wake(t.name); t != nil && t.reachable() { // a leak test is asked for: sleeping tunnels wake up
			routes = append(routes, tunnelPref+t.name)
		}
	}
	b, _ := json.Marshal(probe.LeakTest(ctx, e.ProbeRoute, routes))
	return string(b)
}

// ProbeRoute runs the leak-test probe through one route; the JSON is a
// probe.Result (it fits probe.Runner).
func (e *Engine) ProbeRoute(ctx context.Context, route string) ([]byte, error) {
	dial, res, err := e.routeNet(route)
	if err != nil {
		return nil, err
	}
	return json.Marshal(probe.RunWith(ctx, dial, res))
}
