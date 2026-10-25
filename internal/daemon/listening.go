package daemon

import (
	"net"
	"net/netip"
	"slices"
	"sort"

	"github.com/Bob-Nixkoenner/the_shunt/internal/api"
	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/Bob-Nixkoenner/the_shunt/internal/engine"
	"github.com/Bob-Nixkoenner/the_shunt/internal/sockets"
)

// listening reports the open ports and where they can be reached from.
func (d *Daemon) listening() api.Listening {
	d.mu.Lock()
	out := api.Listening{Ports: []api.OpenPort{}}
	var in *engine.Inbound
	if d.plan != nil {
		in = d.plan.Inbound
	}
	if in != nil {
		out.Inbound = in.Mode
	}
	if d.prep != nil {
		out.Network = d.prep.Network
	}
	if d.plan != nil {
		out.Uplinks = slices.Clone(d.plan.LinkIfaces)
		for _, r := range d.plan.Routes {
			if r.Kind == config.RouteTunnel && r.Iface != "" && !slices.Contains(out.Tunnels, r.Iface) {
				out.Tunnels = append(out.Tunnels, r.Iface)
			}
		}
	}
	d.mu.Unlock()
	out.Firewalls = otherFirewalls()

	ss, err := sockets.ListListening()
	if err != nil {
		out.Error = err.Error()
		return out
	}
	byAddr, byIndex, phys := ifaceAddrs()
	// connected = a physical link with an address, default route or not:
	// neighbours on a network without a gateway reach you all the same
	for _, n := range phys {
		if !slices.Contains(out.Uplinks, n) {
			out.Uplinks = append(out.Uplinks, n)
		}
	}
	sort.Strings(out.Uplinks)
	for _, s := range ss {
		p := api.OpenPort{Proto: s.Proto, Addr: s.Local.Addr().Unmap().String(), Port: s.Local.Port(),
			UID: s.UID, V6Only: s.V6Only, Owner: d.sockets.Owner(s.Cgroup)}
		a := s.Local.Addr().Unmap()
		switch {
		case s.Iface != 0:
			p.Reach, p.Ifaces = "iface", []string{byIndex[s.Iface]}
		case a.IsLoopback():
			p.Reach = "localhost"
		case a.IsUnspecified() || a.IsMulticast():
			p.Reach = "all"
		default:
			p.Reach = "iface"
			if n, ok := byAddr[a]; ok {
				p.Ifaces = []string{n}
			}
		}
		if slices.Contains(p.Ifaces, "lo") {
			p.Reach = "localhost"
		}
		if p.Reach == "all" {
			p.Exposed, p.Tunnel = len(out.Uplinks) > 0, len(out.Tunnels) > 0
		} else {
			for _, i := range p.Ifaces {
				p.Exposed = p.Exposed || slices.Contains(out.Uplinks, i)
				p.Tunnel = p.Tunnel || slices.Contains(out.Tunnels, i)
			}
		}
		if in != nil {
			p.Tunnel = false // tunnels are closed in every mode
		}
		if in != nil && p.Exposed {
			switch in.Mode {
			case config.InboundClosed:
				p.Blocked = true
			case config.InboundLAN:
				p.LANOnly = slices.ContainsFunc(in.Allow, func(a config.PortSel) bool {
					return a.Proto == p.Proto && a.From <= p.Port && p.Port <= a.To
				})
				p.Blocked = !p.LANOnly
			}
		}
		out.Ports = append(out.Ports, p)
	}
	sort.SliceStable(out.Ports, func(i, j int) bool {
		a, b := out.Ports[i], out.Ports[j]
		if a.Exposed != b.Exposed {
			return a.Exposed
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.Proto < b.Proto
	})
	return out
}

// ifaceAddrs maps the machine's addresses and interface indexes to
// interface names, and lists the physical links that are up and have an
// address.
func ifaceAddrs() (map[netip.Addr]string, map[int]string, []string) {
	byAddr, byIndex := map[netip.Addr]string{}, map[int]string{}
	var phys []string
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		byIndex[i.Index] = i.Name
		as, _ := i.Addrs()
		if i.Flags&net.FlagUp != 0 && len(as) > 0 && physicalIface(i.Name) {
			phys = append(phys, i.Name)
		}
		for _, a := range as {
			if n, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(n.IP); ok {
					byAddr[ip.Unmap()] = i.Name
				}
				// sockets bound to the subnet's broadcast address (nmbd)
				if v4 := n.IP.To4(); v4 != nil && len(n.Mask) == net.IPv4len {
					var b [4]byte
					for k := range b {
						b[k] = v4[k] | ^n.Mask[k]
					}
					if _, taken := byAddr[netip.AddrFrom4(b)]; !taken {
						byAddr[netip.AddrFrom4(b)] = i.Name
					}
				}
			}
		}
	}
	return byAddr, byIndex, phys
}
