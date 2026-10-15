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

	"github.com/Bob-Nixkoenner/the_shunt/internal/health"
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
	conf *wgconf.Config // for re-resolving endpoints
	mon  health.Monitor
}

func parseWG(conf string) (*wgconf.Config, error) {
	return wgconf.Parse(strings.NewReader(conf))
}

// resolver asks the DNS server of the direct route, on the direct route;
// Go's default resolver finds no /etc/resolv.conf on Android.
func (e *Engine) resolver() *net.Resolver {
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return e.o.DialDirect(ctx, network, netip.AddrPortFrom(e.directDNS(), 53).String())
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
	t.dev, t.net, t.conf = dev, tnet, c
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

func (t *wgTunnel) status() (st tunnelStatus) {
	st = tunnelStatus{Name: t.name, Up: t.dev != nil, Error: t.err}
	if t.dev == nil {
		st.Health = health.Report{State: health.Down, HandshakeAge: -1}
		return st
	}
	defer func() { st.Health = t.mon.Report(time.Now()) }()
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

// healthLoop watches the tunnels (internal/health): counters every round,
// a DNS probe through tunnels in use, and a reconnect (endpoint names
// resolved again, socket re-opened) when one is down. The first round runs
// at once and probes every tunnel, so the UI shows state and latency right
// after the start instead of one interval later.
func (e *Engine) healthLoop(ctx context.Context, every time.Duration) {
	defer close(e.healthDone)
	tick := time.NewTicker(every)
	defer tick.Stop()
	for first := true; ; first = false {
		if !first {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
		}
		for _, t := range e.tunnels {
			if t.dev == nil {
				continue
			}
			now := time.Now()
			st := t.status()
			var hs time.Time
			if st.Handshake > 0 {
				hs = time.Unix(st.Handshake, 0)
			}
			t.mon.Observe(hs, st.RX, st.TX, now)
			e.book.Observe(t.name, st.RX, st.TX, now)
			if first || t.mon.Active(now) {
				pctx, cancel := context.WithTimeout(ctx, min(5*time.Second, every))
				t.mon.Probed(health.DNSProbe(pctx, t.dialUDP, t.dns))
				cancel()
				if first && st.Handshake == 0 { // the probe made the first handshake: count it now
					if st2 := t.status(); st2.Handshake > 0 {
						t.mon.Observe(time.Unix(st2.Handshake, 0), st2.RX, st2.TX, time.Now())
						e.book.Observe(t.name, st2.RX, st2.TX, time.Now())
					}
				}
			}
			if t.mon.ShouldReconnect(time.Now()) {
				e.logf("tunnel %s: no answers, reconnecting", t.name)
				if err := e.reconnect(t); err != nil {
					e.logf("tunnel %s: reconnect: %v", t.name, err)
				}
			}
		}
	}
}

func (t *wgTunnel) dialUDP(_ context.Context, _, addr string) (net.Conn, error) {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return nil, err
	}
	return t.net.DialUDPAddrPort(netip.AddrPort{}, ap)
}

// reconnect resolves the endpoints again (DDNS) and re-opens the socket.
func (e *Engine) reconnect(t *wgTunnel) error {
	var b strings.Builder
	for _, p := range t.conf.Peers {
		if p.Endpoint == "" {
			continue
		}
		ep, err := resolveEndpoint(p.Endpoint, e.resolver())
		if err != nil {
			return err
		}
		fmt.Fprintf(&b, "public_key=%s\nendpoint=%s\n", hex.EncodeToString(p.PublicKey[:]), ep)
	}
	if b.Len() > 0 {
		if err := t.dev.IpcSet(b.String()); err != nil {
			return err
		}
	}
	if err := t.dev.BindUpdate(); err != nil {
		return err
	}
	if e.o.BindUp != nil {
		return e.o.BindUp(t.dev.Bind())
	}
	return nil
}
