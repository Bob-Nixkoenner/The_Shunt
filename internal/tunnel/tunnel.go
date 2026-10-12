// Package tunnel brings WireGuard interfaces up and down. The kernel module
// is preferred; wireguard-go runs in-process as fallback (and is what the
// non-Linux backends will use). Both are driven through the same
// wgtypes.Config, so everything above this package does not care which one runs.
package tunnel

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/Bob-Nixkoenner/the_shunt/internal/wgconf"
)

// DefaultMTU matches wg-quick's usual choice for IPv4+IPv6 underlay.
const DefaultMTU = 1420

// Spec describes one tunnel to bring up.
type Spec struct {
	Name   string
	Iface  string
	Driver string // auto | kernel | userspace
	Conf   *wgconf.Config
	Mark   uint32 // firewall mark for the encrypted UDP socket
}

// Device is a running tunnel of any kind (WireGuard or OpenVPN).
type Device interface {
	DriverName() string
	Down()
	Alive() bool
	Status() ([]PeerStatus, error)
	Reresolve(now time.Time) ([]string, error)
	Err() string // current problem worth showing, or ""
}

// Tunnel is a running WireGuard interface.
type Tunnel struct {
	Spec   Spec
	Driver string // the driver actually used

	dev *device.Device
	ctl control
	// resolved endpoint per peer public key, to detect DDNS changes
	endpoints map[wgtypes.Key]string
}

// Up creates and configures the interface.
func Up(s Spec, log *slog.Logger) (*Tunnel, error) {
	mtu := s.Conf.MTU
	if mtu == 0 {
		mtu = DefaultMTU
	}
	// Leftover from a crash: start clean.
	if l, err := netlink.LinkByName(s.Iface); err == nil {
		_ = netlink.LinkDel(l)
	}
	t := &Tunnel{Spec: s, endpoints: map[wgtypes.Key]string{}}
	var err error
	switch s.Driver {
	case "kernel":
		err = t.upKernel(mtu)
	case "userspace":
		err = t.upUserspace(mtu, log)
	default:
		if err = t.upKernel(mtu); err != nil {
			log.Info("kernel wireguard unavailable, using wireguard-go", "tunnel", s.Name, "err", err)
			err = t.upUserspace(mtu, log)
		}
	}
	if err != nil {
		return nil, err
	}
	if err := t.configure(); err != nil {
		t.Down()
		return nil, err
	}
	return t, nil
}

func (t *Tunnel) upKernel(mtu int) error {
	la := netlink.NewLinkAttrs()
	la.Name = t.Spec.Iface
	la.MTU = mtu
	if err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: la}); err != nil {
		return err
	}
	t.Driver = "kernel"
	t.ctl = kernelControl{iface: t.Spec.Iface}
	return nil
}

func (t *Tunnel) upUserspace(mtu int, log *slog.Logger) error {
	tdev, err := tun.CreateTUN(t.Spec.Iface, mtu)
	if err != nil {
		return fmt.Errorf("create tun: %w", err)
	}
	logger := &device.Logger{
		Verbosef: func(string, ...any) {},
		Errorf: func(f string, a ...any) {
			log.Error(fmt.Sprintf(f, a...), "tunnel", t.Spec.Name)
		},
	}
	t.dev = device.NewDevice(tdev, conn.NewDefaultBind(), logger)
	t.Driver = "userspace"
	t.ctl = userspaceControl{dev: t.dev}
	return nil
}

func (t *Tunnel) configure() error {
	c := t.Spec.Conf
	link, err := netlink.LinkByName(t.Spec.Iface)
	if err != nil {
		return err
	}
	mark := int(t.Spec.Mark)
	cfg := wgtypes.Config{
		PrivateKey:   (*wgtypes.Key)(&c.PrivateKey),
		FirewallMark: &mark,
		ReplacePeers: true,
	}
	if c.ListenPort != 0 {
		cfg.ListenPort = &c.ListenPort
	}
	for _, p := range c.Peers {
		pc := wgtypes.PeerConfig{
			PublicKey:         wgtypes.Key(p.PublicKey),
			ReplaceAllowedIPs: true,
		}
		if !p.PresharedKey.IsZero() {
			psk := wgtypes.Key(p.PresharedKey)
			pc.PresharedKey = &psk
		}
		if p.PersistentKeepalive > 0 {
			ka := time.Duration(p.PersistentKeepalive) * time.Second
			pc.PersistentKeepaliveInterval = &ka
		}
		if p.Endpoint != "" {
			ep, err := net.ResolveUDPAddr("udp", p.Endpoint)
			if err != nil {
				return fmt.Errorf("resolve endpoint %s: %w", p.Endpoint, err)
			}
			pc.Endpoint = ep
			t.endpoints[pc.PublicKey] = ep.String()
		}
		for _, a := range p.AllowedIPs {
			pc.AllowedIPs = append(pc.AllowedIPs, prefixToIPNet(a))
		}
		cfg.Peers = append(cfg.Peers, pc)
	}
	if err := t.ctl.configure(cfg); err != nil {
		return fmt.Errorf("configure %s: %w", t.Spec.Iface, err)
	}
	for _, a := range c.Addresses {
		addr := &netlink.Addr{IPNet: prefixToIPNetPtr(a)}
		if a.Addr().Is6() {
			addr.Flags = 0x80 // IFA_F_NODAD: no DAD delay on a point-to-point tunnel
		}
		if err := netlink.AddrReplace(link, addr); err != nil {
			return fmt.Errorf("address %s: %w", a, err)
		}
	}
	return netlink.LinkSetUp(link)
}

// DriverName implements Device.
func (t *Tunnel) DriverName() string { return t.Driver }

// Err implements Device.
func (t *Tunnel) Err() string { return "" }

// Down removes the interface.
func (t *Tunnel) Down() {
	if t.dev != nil {
		t.dev.Close() // also removes the TUN interface
	}
	if l, err := netlink.LinkByName(t.Spec.Iface); err == nil {
		_ = netlink.LinkDel(l)
	}
}

// PeerStatus is runtime info for one peer.
type PeerStatus struct {
	PublicKey     string    `json:"public_key"`
	Endpoint      string    `json:"endpoint"`
	LastHandshake time.Time `json:"last_handshake"`
	RxBytes       int64     `json:"rx_bytes"`
	TxBytes       int64     `json:"tx_bytes"`
	// KeepaliveSec > 0: the peer is pinged regularly, so a handshake older
	// than ~2 minutes really means "no connection". Without keepalive an
	// idle tunnel simply has no recent handshake.
	KeepaliveSec int `json:"keepalive_sec,omitempty"`
}

// Status reads peer state through wgctrl.
func (t *Tunnel) Status() ([]PeerStatus, error) {
	d, err := t.ctl.device()
	if err != nil {
		return nil, err
	}
	var out []PeerStatus
	for _, p := range d.Peers {
		ps := PeerStatus{PublicKey: p.PublicKey.String(), LastHandshake: p.LastHandshakeTime, RxBytes: p.ReceiveBytes, TxBytes: p.TransmitBytes, KeepaliveSec: int(p.PersistentKeepaliveInterval.Seconds())}
		if p.Endpoint != nil {
			ps.Endpoint = p.Endpoint.String()
		}
		out = append(out, ps)
	}
	return out, nil
}

// StaleHandshake is when the watchdog re-resolves endpoint names. WireGuard
// re-keys every 2 minutes, so anything older means the peer is unreachable.
const StaleHandshake = 150 * time.Second

// Reresolve looks up endpoint host names again for peers without a recent
// handshake and updates the device if the address changed (DDNS, forced
// ISP reconnects). It returns the peers whose endpoint changed.
func (t *Tunnel) Reresolve(now time.Time) ([]string, error) {
	d, err := t.ctl.device()
	if err != nil {
		return nil, err
	}
	hs := map[wgtypes.Key]time.Time{}
	for _, p := range d.Peers {
		hs[p.PublicKey] = p.LastHandshakeTime
	}
	var cfg wgtypes.Config
	var changed []string
	var errs []error
	for _, p := range t.Spec.Conf.Peers {
		k := wgtypes.Key(p.PublicKey)
		if p.Endpoint == "" || now.Sub(hs[k]) < StaleHandshake {
			continue
		}
		host, _, _ := net.SplitHostPort(p.Endpoint)
		if _, err := netip.ParseAddr(host); err == nil {
			continue // literal IP, nothing to re-resolve
		}
		ep, err := net.ResolveUDPAddr("udp", p.Endpoint)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if t.endpoints[k] == ep.String() {
			continue
		}
		changed = append(changed, fmt.Sprintf("%s: %s -> %s", p.Endpoint, t.endpoints[k], ep))
		t.endpoints[k] = ep.String()
		cfg.Peers = append(cfg.Peers, wgtypes.PeerConfig{PublicKey: k, UpdateOnly: true, Endpoint: ep})
	}
	if len(cfg.Peers) > 0 {
		if err := t.ctl.configure(cfg); err != nil {
			return nil, err
		}
	}
	return changed, errors.Join(errs...)
}

func prefixToIPNet(p netip.Prefix) net.IPNet {
	return net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}

func prefixToIPNetPtr(p netip.Prefix) *net.IPNet {
	n := prefixToIPNet(p)
	return &n
}

// Alive reports whether the interface still exists. It can vanish under us
// (someone ran `ip link del`, a crashed driver); its traffic is blocked by the
// kill switch table until the daemon brings it back.
func (t *Tunnel) Alive() bool {
	_, err := netlink.LinkByName(t.Spec.Iface)
	return err == nil
}
