// Package links finds the machine's network connections by kind – Wi-Fi,
// cable, mobile – for link routes ("link:wifi" sends a program out over
// the Wi-Fi, whatever else is connected).
package links

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Link is the connection currently used for one kind.
type Link struct {
	Kind  string // config.LinkKinds
	Name  string // interface
	Index int
	// Gateways of the interface's default routes (change detection).
	Gateways []string
	// DNS servers the network gave this interface (DHCP/RA).
	DNS []netip.Addr
}

// State maps a kind to its connected link; kinds without one are missing.
type State map[string]Link

// Iface returns the interface of kind, "" when not connected.
func (s State) Iface(kind string) string { return s[kind].Name }

// Key changes whenever the choice of interfaces, their gateways or DNS
// servers change.
func (s State) Key() string {
	kinds := make([]string, 0, len(s))
	for k := range s {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	var b strings.Builder
	for _, k := range kinds {
		l := s[k]
		fmt.Fprintf(&b, "%s=%s/%d/%s/%v;", k, l.Name, l.Index, strings.Join(l.Gateways, ","), l.DNS)
	}
	return b.String()
}

// Names is Key without the gateways: what the firewall rules depend on.
func (s State) Names() string {
	kinds := make([]string, 0, len(s))
	for k := range s {
		kinds = append(kinds, k+"="+s[k].Name)
	}
	sort.Strings(kinds)
	return strings.Join(kinds, ";")
}

// candidate is an interface with a default route, before choosing.
type candidate struct {
	Link
	metric int
}

// choose picks per kind the candidate with the lowest default route metric.
func choose(cs []candidate) State {
	sort.SliceStable(cs, func(i, j int) bool {
		if cs[i].metric != cs[j].metric {
			return cs[i].metric < cs[j].metric
		}
		return cs[i].Name < cs[j].Name
	})
	s := State{}
	for _, c := range cs {
		if _, ok := s[c.Kind]; !ok && c.Kind != "" {
			s[c.Kind] = c.Link
		}
	}
	return s
}
