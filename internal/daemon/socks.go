package daemon

import (
	"context"
	"errors"
	"net/netip"

	"github.com/miekg/dns"

	"github.com/Bob-Nixkoenner/the_shunt/internal/dnsproxy"
	"github.com/Bob-Nixkoenner/the_shunt/internal/socks"
)

// socksExits lists the SOCKS5 exits of the plan's tunnels. A tunnel that is
// disabled or unknown to the plan gets none.
func socksExits(p *Prepared, ups dnsproxy.RouteUpstreams) map[string]socks.Exit {
	out := map[string]socks.Exit{}
	for name, t := range p.Config.Tunnels {
		if t.Socks == "" || t.Disabled {
			continue
		}
		route := "tunnel:" + name
		r := p.Plan.RouteByName(route)
		if r == nil {
			continue
		}
		us := ups[route]
		out[name] = socks.Exit{Listen: t.Socks, Mark: r.Mark, Resolve: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return resolveVia(ctx, us, host)
		}}
	}
	return out
}

// resolveVia asks the tunnel's DNS upstreams (marked for the tunnel), A and
// AAAA, so a name never leaves through the local network.
func resolveVia(ctx context.Context, ups []dnsproxy.Upstream, host string) ([]netip.Addr, error) {
	var addrs []netip.Addr
	for _, u := range ups {
		for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn(host), qt)
			resp, err := u.Exchange(ctx, m)
			if err != nil {
				continue
			}
			for _, rr := range resp.Answer {
				switch v := rr.(type) {
				case *dns.A:
					if a, ok := netip.AddrFromSlice(v.A); ok {
						addrs = append(addrs, a.Unmap())
					}
				case *dns.AAAA:
					if a, ok := netip.AddrFromSlice(v.AAAA); ok {
						addrs = append(addrs, a)
					}
				}
			}
		}
		if len(addrs) > 0 {
			return addrs, nil
		}
	}
	return nil, errors.New("no address for " + host)
}
