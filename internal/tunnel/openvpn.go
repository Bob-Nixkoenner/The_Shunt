package tunnel

import "net/netip"

// OpenVPNSpec describes an OpenVPN tunnel.
type OpenVPNSpec struct {
	Name     string
	Iface    string
	Config   string // .ovpn path, checked by ovpnconf
	AuthFile string // username/password file for auth-user-pass, or ""
	Mark     uint32 // mark for the encrypted packets (bypass, or a hop's route)
	PIDDir   string // where the pid file of the running openvpn goes
}

// NetChecker is a tunnel that wants to look at the machine's addresses on
// every network tick (OpenVPN over TCP: a connection tied to a source
// address that is gone after a network change is restarted at once).
type NetChecker interface {
	CheckNetwork()
}

// Pusher is a tunnel whose server tells the DNS servers at run time
// (OpenVPN). The daemon routes the tunnel's DNS there.
type Pusher interface {
	Connected() bool
	DNS() []netip.Addr
}
