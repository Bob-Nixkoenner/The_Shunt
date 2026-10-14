package splitstack

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/wgconf"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// wgTunnel is one WireGuard tunnel with its own userspace netstack.
type wgTunnel struct {
	name string
	err  string // why it is not up
	dev  *device.Device
	net  *netstack.Net
	dns  netip.Addr // DNS server reached through this tunnel
	v4   bool
	v6   bool
}

func parseWG(conf string) (*wgconf.Config, error) {
	return wgconf.Parse(strings.NewReader(conf))
}

// resolver asks the DNS server of the direct route, on the direct route;
// Go's default resolver finds no /etc/resolv.conf on Android.
func (e *Engine) resolver() *net.Resolver {
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return e.o.DialDirect(ctx, network, netip.AddrPortFrom(e.direct, 53).String())
	}}
}

func newWGTunnel(name, conf string, r *net.Resolver, bind conn.Bind, bindUp func(conn.Bind) error, mtu int) (*wgTunnel, error) {
	c, err := parseWG(conf)
	if err != nil {
		return nil, err
	}
	if len(c.Peers) == 0 || len(c.Addresses) == 0 {
		return nil, errors.New("needs an Address and a [Peer]")
	}
	if c.MTU > 0 && c.MTU < mtu {
		mtu = c.MTU
	}
	t := &wgTunnel{name: name, dns: netip.MustParseAddr("1.1.1.1")}
	for _, d := range c.DNS {
		if a, err := netip.ParseAddr(d); err == nil {
			t.dns = a
			break
		}
	}
	var addrs []netip.Addr
	for _, a := range c.Addresses {
		addrs = append(addrs, a.Addr())
		t.v4 = t.v4 || a.Addr().Is4()
		t.v6 = t.v6 || a.Addr().Is6()
	}
	uapi, err := uapiConfig(c, r)
	if err != nil {
		return nil, err
	}
	tdev, tnet, err := netstack.CreateNetTUN(addrs, []netip.Addr{t.dns}, mtu)
	if err != nil {
		return nil, err
	}
	logger := &device.Logger{Verbosef: device.DiscardLogf, Errorf: device.DiscardLogf}
	dev := device.NewDevice(tdev, bind, logger)
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		return nil, err
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, err
	}
	if bindUp != nil {
		if err := bindUp(bind); err != nil {
			dev.Close()
			return nil, err
		}
	}
	t.dev, t.net = dev, tnet
	return t, nil
}

// uapiConfig turns a wg-quick file into wireguard-go's UAPI text, with
// endpoint names resolved.
func uapiConfig(c *wgconf.Config, r *net.Resolver) (string, error) {
	var b strings.Builder
	kv := func(k, v string) { fmt.Fprintf(&b, "%s=%s\n", k, v) }
	kv("private_key", hex.EncodeToString(c.PrivateKey[:]))
	kv("replace_peers", "true")
	for _, p := range c.Peers {
		kv("public_key", hex.EncodeToString(p.PublicKey[:]))
		if !p.PresharedKey.IsZero() {
			kv("preshared_key", hex.EncodeToString(p.PresharedKey[:]))
		}
		if p.Endpoint != "" {
			ep, err := resolveEndpoint(p.Endpoint, r)
			if err != nil {
				return "", err
			}
			kv("endpoint", ep.String())
		}
		if p.PersistentKeepalive > 0 {
			kv("persistent_keepalive_interval", strconv.Itoa(p.PersistentKeepalive))
		}
		kv("replace_allowed_ips", "true")
		for _, a := range p.AllowedIPs {
			kv("allowed_ip", a.String())
		}
	}
	return b.String(), nil
}

func resolveEndpoint(ep string, r *net.Resolver) (netip.AddrPort, error) {
	if ap, err := netip.ParseAddrPort(ep); err == nil {
		return ap, nil
	}
	host, port, err := net.SplitHostPort(ep)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("endpoint %q: %w", ep, err)
	}
	pn, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("endpoint %q: bad port", ep)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	ips, err := r.LookupNetIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return netip.AddrPort{}, fmt.Errorf("endpoint %q: cannot resolve: %v", ep, err)
	}
	ip := ips[0]
	for _, a := range ips { // IPv4 first: mobile networks often lack IPv6 to the server
		if a.Is4() {
			ip = a
			break
		}
	}
	return netip.AddrPortFrom(ip.Unmap(), uint16(pn)), nil
}

func (t *wgTunnel) close() {
	if t.dev != nil {
		t.dev.Close()
	}
}

func (t *wgTunnel) status() tunnelStatus {
	st := tunnelStatus{Name: t.name, Up: t.dev != nil, Error: t.err}
	if t.dev == nil {
		return st
	}
	s, err := t.dev.IpcGet()
	if err != nil {
		return st
	}
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		k, v, _ := strings.Cut(sc.Text(), "=")
		n, _ := strconv.ParseInt(v, 10, 64)
		switch k {
		case "last_handshake_time_sec":
			st.Handshake = max(st.Handshake, n)
		case "rx_bytes":
			st.RX += n
		case "tx_bytes":
			st.TX += n
		}
	}
	return st
}
