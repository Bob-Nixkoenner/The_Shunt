package wfp

import (
	"fmt"
	"net/netip"
)

// Exit guard (report M-04, Windows counterpart of the Linux shunt_torguard
// table): the loopback addresses of the SOCKS exits (tunnel.socks) and of
// tor.exe's SOCKS ports belong to the service. Another program that bound
// one first (or bound it with SO_REUSEADDR next to ours) would get the
// connections of programs set up for the exit, in plain text and outside
// the tunnel. The filters are described here without Windows types so they
// can be tested everywhere; exitguard_windows.go installs them.
//
// Per guarded address:
//   - ALE_AUTH_RECV_ACCEPT (the listening side): a connection to the
//     address may only be accepted by one of Owners running as the
//     service's account (SYSTEM);
//     every other listener is blocked. This holds however the other program
//     got the port (before us, after a restart, by SO_REUSEADDR).
//   - Taken (the service could not bind it): ALE_AUTH_CONNECT blocks
//     connecting to it at all, except the service itself, so the
//     programs set up for the exit fail at once instead of hanging.

// ExitGuard is one guarded TCP address. Owners are the program paths that
// may accept on it ("" = the service itself).
type ExitGuard struct {
	Addr   netip.AddrPort
	Owners []string
	Taken  bool
}

// ExitLayer is the WFP layer an exit guard filter sits at.
type ExitLayer uint8

const (
	ExitLayerAccept  ExitLayer = iota // FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4/V6
	ExitLayerConnect                  // FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6
)

// ExitFilter is one filter. Permit filters carry App (a program path, ""
// = the service) and the SYSTEM condition; block filters match the address
// alone. Addr is the local address at the accept layer and the remote one
// at the connect layer; an unspecified address matches the port alone.
type ExitFilter struct {
	Layer  ExitLayer
	V6     bool
	Addr   netip.AddrPort
	Permit bool
	App    string
	Weight uint8
	Index  uint32
	Name   string
}

// ExitMaxIndex bounds the filter keys (exBase + index).
const ExitMaxIndex = 256

// Weights inside the own sublayer: the owner permits before the block.
const (
	exitWeightPermit = 15
	exitWeightBlock  = 10
)

// ExitFilters returns the filters for gs in install order. Invalid
// addresses are skipped; an error means more filters than keys.
func ExitFilters(gs []ExitGuard) ([]ExitFilter, error) {
	var out []ExitFilter
	add := func(f ExitFilter) {
		f.Index = uint32(len(out))
		out = append(out, f)
	}
	for _, g := range gs {
		if !g.Addr.IsValid() || g.Addr.Port() == 0 {
			continue
		}
		a := netip.AddrPortFrom(g.Addr.Addr().Unmap(), g.Addr.Port())
		v6 := a.Addr().Is6()
		owners := g.Owners
		if len(owners) == 0 {
			owners = []string{""}
		}
		for _, o := range owners {
			add(ExitFilter{Layer: ExitLayerAccept, V6: v6, Addr: a, Permit: true, App: o, Weight: exitWeightPermit,
				Name: fmt.Sprintf("Exit guard: owner may accept on %s", a)})
		}
		add(ExitFilter{Layer: ExitLayerAccept, V6: v6, Addr: a, Weight: exitWeightBlock,
			Name: fmt.Sprintf("Exit guard: block other listeners on %s", a)})
		if g.Taken {
			add(ExitFilter{Layer: ExitLayerConnect, V6: v6, Addr: a, Permit: true, App: "", Weight: exitWeightPermit,
				Name: fmt.Sprintf("Exit guard: service may connect to %s", a)})
			add(ExitFilter{Layer: ExitLayerConnect, V6: v6, Addr: a, Weight: exitWeightBlock,
				Name: fmt.Sprintf("Exit guard: block connecting to the taken address %s", a)})
		}
	}
	if len(out) > ExitMaxIndex {
		return nil, fmt.Errorf("exit guard: %d filters, at most %d", len(out), ExitMaxIndex)
	}
	return out, nil
}
