package tunnel

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// control configures and reads a WireGuard device. The kernel driver uses
// wgctrl (genetlink). The in-process wireguard-go device is driven directly
// through its IPC methods: no UAPI socket in /var/run/wireguard, which would
// be one more root-owned control channel (and is shared across network
// namespaces).
type control interface {
	configure(wgtypes.Config) error
	device() (*wgtypes.Device, error)
}

type kernelControl struct{ iface string }

func (k kernelControl) configure(c wgtypes.Config) error {
	wc, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer wc.Close()
	return wc.ConfigureDevice(k.iface, c)
}

func (k kernelControl) device() (*wgtypes.Device, error) {
	wc, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	defer wc.Close()
	return wc.Device(k.iface)
}

type ipcDevice interface {
	IpcSet(string) error
	IpcGet() (string, error)
}

type userspaceControl struct{ dev ipcDevice }

func (u userspaceControl) configure(c wgtypes.Config) error {
	return u.dev.IpcSet(uapiConfig(c))
}

func (u userspaceControl) device() (*wgtypes.Device, error) {
	s, err := u.dev.IpcGet()
	if err != nil {
		return nil, err
	}
	return parseUAPI(s)
}

// uapiConfig serializes a config in the cross-platform UAPI text format
// (https://www.wireguard.com/xplatform/).
func uapiConfig(c wgtypes.Config) string {
	var b strings.Builder
	kv := func(k, v string) { fmt.Fprintf(&b, "%s=%s\n", k, v) }
	if c.PrivateKey != nil {
		kv("private_key", hex.EncodeToString(c.PrivateKey[:]))
	}
	if c.ListenPort != nil {
		kv("listen_port", strconv.Itoa(*c.ListenPort))
	}
	if c.FirewallMark != nil {
		kv("fwmark", strconv.Itoa(*c.FirewallMark))
	}
	if c.ReplacePeers {
		kv("replace_peers", "true")
	}
	for _, p := range c.Peers {
		kv("public_key", hex.EncodeToString(p.PublicKey[:]))
		if p.UpdateOnly {
			kv("update_only", "true")
		}
		if p.PresharedKey != nil {
			kv("preshared_key", hex.EncodeToString(p.PresharedKey[:]))
		}
		if p.Endpoint != nil {
			kv("endpoint", p.Endpoint.String())
		}
		if p.PersistentKeepaliveInterval != nil {
			kv("persistent_keepalive_interval", strconv.Itoa(int(p.PersistentKeepaliveInterval.Seconds())))
		}
		if p.ReplaceAllowedIPs {
			kv("replace_allowed_ips", "true")
		}
		for _, a := range p.AllowedIPs {
			kv("allowed_ip", a.String())
		}
	}
	return b.String()
}

// parseUAPI reads the subset of an IpcGet dump that Status and the
// watchdog need.
func parseUAPI(s string) (*wgtypes.Device, error) {
	d := &wgtypes.Device{Type: wgtypes.Userspace}
	var p *wgtypes.Peer
	var hsSec, hsNsec int64
	flush := func() {
		if p != nil {
			p.LastHandshakeTime = time.Unix(hsSec, hsNsec)
			if hsSec == 0 && hsNsec == 0 {
				p.LastHandshakeTime = time.Time{}
			}
			d.Peers = append(d.Peers, *p)
		}
		hsSec, hsNsec = 0, 0
	}
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		switch k {
		case "public_key":
			flush()
			key, err := hexKey(v)
			if err != nil {
				return nil, err
			}
			p = &wgtypes.Peer{PublicKey: key}
		case "endpoint":
			if p != nil {
				p.Endpoint, _ = net.ResolveUDPAddr("udp", v)
			}
		case "last_handshake_time_sec":
			hsSec, _ = strconv.ParseInt(v, 10, 64)
		case "last_handshake_time_nsec":
			hsNsec, _ = strconv.ParseInt(v, 10, 64)
		case "rx_bytes":
			if p != nil {
				p.ReceiveBytes, _ = strconv.ParseInt(v, 10, 64)
			}
		case "tx_bytes":
			if p != nil {
				p.TransmitBytes, _ = strconv.ParseInt(v, 10, 64)
			}
		case "fwmark":
			d.FirewallMark, _ = strconv.Atoi(v)
		case "listen_port":
			d.ListenPort, _ = strconv.Atoi(v)
		}
	}
	flush()
	return d, sc.Err()
}

func hexKey(s string) (wgtypes.Key, error) {
	var k wgtypes.Key
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(k) {
		return k, fmt.Errorf("bad key in uapi dump")
	}
	copy(k[:], b)
	return k, nil
}
