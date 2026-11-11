package defense

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// New network interface watch (a USB Ethernet adapter, a Pi Zero in gadget
// mode and similar devices bring their own link, and often their own DHCP
// server and default route). The watch itself follows netlink link and route
// events (Linux, ifaceWatch in iface_linux.go).
//
// What the interface IS, is read from sysfs and is an ASSUMPTION, not
// something the kernel documentation or the research notes confirm:
//   - /sys/devices/virtual/net/<if> means a virtual device (tunnel, veth,
//     bridge): ignored, so the Shunt's own tunnel never alarms;
//   - the device/subsystem link pointing to "usb" (or a "usbN" component in
//     the resolved path) is taken as "attached over USB";
//   - a wireless/ or phy80211 entry is taken as Wi-Fi;
//   - the driver name comes from device/driver (it may appear a moment after
//     the link, so the watch waits before reading it) or the uevent file.
//
// Where sysfs gives nothing, the type is "unknown" and no bus is claimed.
// The real test with a USB gadget (Pi Zero 2 W, ECM/RNDIS) is still to be
// done on a real device.

// IfaceInfo describes one interface as far as sysfs tells.
type IfaceInfo struct {
	Type    string // "ethernet", "wlan", "virtual" or "unknown"
	Bus     string // "usb" or "" (no claim)
	Driver  string // may be ""
	Virtual bool
}

var usbComp = regexp.MustCompile(`^usb\d+$`)

// ClassifyIface reads /sys (sysRoot, "/sys" in production) for one interface.
func ClassifyIface(sysRoot, name string) IfaceInfo {
	if name == "" || strings.ContainsAny(name, "/\x00") || name == "." || name == ".." {
		return IfaceInfo{Type: "unknown"}
	}
	base := filepath.Join(sysRoot, "class", "net", name)
	real, err := filepath.EvalSymlinks(base)
	if err != nil {
		return IfaceInfo{Type: "unknown"}
	}
	if strings.Contains(filepath.ToSlash(real), "/virtual/") {
		return IfaceInfo{Type: "virtual", Virtual: true}
	}
	info := IfaceInfo{Type: "unknown"}
	if _, err := os.Stat(filepath.Join(base, "wireless")); err == nil {
		info.Type = "wlan"
	} else if _, err := os.Stat(filepath.Join(base, "phy80211")); err == nil {
		info.Type = "wlan"
	} else if b, err := os.ReadFile(filepath.Join(base, "type")); err == nil && strings.TrimSpace(string(b)) == "1" {
		info.Type = "ethernet"
	}
	if l, err := os.Readlink(filepath.Join(base, "device", "subsystem")); err == nil && filepath.Base(l) == "usb" {
		info.Bus = "usb"
	}
	if info.Bus == "" {
		for _, c := range strings.Split(filepath.ToSlash(real), "/") {
			if usbComp.MatchString(c) {
				info.Bus = "usb"
				break
			}
		}
	}
	if l, err := os.Readlink(filepath.Join(base, "device", "driver")); err == nil {
		info.Driver = filepath.Base(l)
	} else if b, err := os.ReadFile(filepath.Join(base, "device", "uevent")); err == nil {
		for _, ln := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(ln, "DRIVER="); ok {
				info.Driver = strings.TrimSpace(v)
			}
		}
	}
	if len(info.Driver) > 32 || strings.ContainsAny(info.Driver, " =") {
		info.Driver = ""
	}
	return info
}

// detail is the event text. It never names the interface (names such as
// enx<MAC> carry the hardware address).
func (i IfaceInfo) detail() string {
	d := "type=" + i.Type
	if i.Bus != "" {
		d += " bus=" + i.Bus
	}
	if i.Driver != "" {
		d += " driver=" + i.Driver
	}
	return d
}

// ifaceWatch decides which interfaces count as new.
type ifaceWatch struct {
	mu   sync.Mutex
	base map[string]bool // present at start
	said map[string]bool
}

func newIfaceWatch(present []string) *ifaceWatch {
	w := &ifaceWatch{base: map[string]bool{}, said: map[string]bool{}}
	for _, n := range present {
		w.base[n] = true
	}
	return w
}

// IsNew reports whether name appeared after start (virtual ones the caller
// has filtered out already).
func (w *ifaceWatch) IsNew(name string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return name != "" && !w.base[name]
}

// Link returns the event for a new interface, once per name.
func (w *ifaceWatch) Link(name string, i IfaceInfo) (Event, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if name == "" || w.base[name] || i.Virtual || w.said["l|"+name] || len(w.said) > 64 {
		return Event{}, false
	}
	w.said["l|"+name] = true
	sev := SevLow
	if i.Bus == "usb" {
		sev = SevMedium
	}
	return Event{Kind: KindNewIface, Severity: sev, Detail: "new interface " + i.detail()}, true
}

// DefaultRoute returns the high event when a new interface gets a default
// route, once per name.
func (w *ifaceWatch) DefaultRoute(name string, i IfaceInfo) (Event, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if name == "" || w.base[name] || i.Virtual || w.said["r|"+name] || len(w.said) > 64 {
		return Event{}, false
	}
	w.said["r|"+name] = true
	return Event{Kind: KindNewIface, Severity: SevHigh, Detail: "default route via a new interface " + i.detail()}, true
}
