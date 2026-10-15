package winsplit

import (
	"fmt"
	"os/exec"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
)

// AdapterName is the wintun adapter all traffic is steered into.
const AdapterName = "Shunt"

// MTU of the adapter (WireGuard inside needs room).
const MTU = 1280

// Adapter is the wintun adapter with its addresses and routes.
type Adapter struct {
	Dev  tun.Device
	Phys uint32 // interface index of the real network (where direct goes)
}

// Close removes the adapter and with it its addresses and routes.
func (a *Adapter) Close() error { return a.Dev.Close() }

func netsh(args ...string) error {
	if out, err := exec.Command("netsh", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("netsh %v: %v: %s", args, err, out)
	}
	return nil
}

// OpenAdapter creates the wintun adapter "Shunt" with routes 0.0.0.0/1 +
// 128.0.0.0/1 and ::/1 + 8000::/1 (more specific than any default route,
// so all traffic enters the split) and dns as its DNS server. Needs
// Administrator (or SYSTEM) and wintun.dll next to the exe.
func OpenAdapter(dns string) (*Adapter, error) {
	var phys uint32
	if err := windows.GetBestInterfaceEx(&windows.SockaddrInet4{Addr: [4]byte{1, 1, 1, 1}}, &phys); err != nil {
		return nil, fmt.Errorf("no default route: %w", err)
	}
	dev, err := tun.CreateTUN(AdapterName, MTU)
	if err != nil {
		return nil, fmt.Errorf("wintun: %w (Administrator? wintun.dll next to the exe?)", err)
	}
	a := &Adapter{Dev: dev, Phys: phys}
	for _, args := range [][]string{
		{"interface", "ipv4", "set", "address", "name=" + AdapterName, "static", "10.111.0.2", "255.255.255.0"},
		{"interface", "ipv4", "set", "dnsservers", "name=" + AdapterName, "static", dns, "validate=no"},
		{"interface", "ipv4", "add", "route", "0.0.0.0/1", AdapterName, "10.111.0.1", "metric=1"},
		{"interface", "ipv4", "add", "route", "128.0.0.0/1", AdapterName, "10.111.0.1", "metric=1"},
		{"interface", "ipv6", "add", "address", AdapterName, "fd11:5ee:bad:c0de::2/64"},
		{"interface", "ipv6", "add", "route", "::/1", AdapterName, "fd11:5ee:bad:c0de::1", "metric=1"},
		{"interface", "ipv6", "add", "route", "8000::/1", AdapterName, "fd11:5ee:bad:c0de::1", "metric=1"},
	} {
		if err := netsh(args...); err != nil {
			dev.Close()
			return nil, err
		}
	}
	return a, nil
}
