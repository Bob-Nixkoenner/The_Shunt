package defense

import (
	"os"
	"path/filepath"
	"testing"
)

// fakeSys builds a small /sys tree: class/net/<n> -> devices/..., with
// optional files.
func fakeSys(t *testing.T, name, devPath string, files map[string]string, links map[string]string) string {
	t.Helper()
	root := t.TempDir()
	dev := filepath.Join(root, devPath)
	if err := os.MkdirAll(dev, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "class", "net"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(dev, filepath.Join(root, "class", "net", name)); err != nil {
		t.Fatal(err)
	}
	for f, c := range files {
		p := filepath.Join(dev, f)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for l, target := range links {
		p := filepath.Join(dev, l)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.Symlink(target, p); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestClassifyIface(t *testing.T) {
	// USB Ethernet gadget: subsystem link says usb, driver link says cdc_ether
	root := fakeSys(t, "usb0", "devices/pci0000:00/0000:00:14.0/usb1/1-1/1-1:1.0/net/usb0",
		map[string]string{"type": "1\n"},
		map[string]string{"device/subsystem": "../../../../../bus/usb", "device/driver": "../../../../../bus/usb/drivers/cdc_ether"})
	if i := ClassifyIface(root, "usb0"); i.Type != "ethernet" || i.Bus != "usb" || i.Driver != "cdc_ether" {
		t.Fatalf("%+v", i)
	}
	// no subsystem link, but a usbN path component: still usb
	root = fakeSys(t, "enx02", "devices/pci0000:00/usb2/2-1/net/enx02", map[string]string{"type": "1\n"}, nil)
	if i := ClassifyIface(root, "enx02"); i.Bus != "usb" || i.Type != "ethernet" || i.Driver != "" {
		t.Fatalf("%+v", i)
	}
	// PCI Wi-Fi with a wireless dir and the driver in uevent: no USB claim
	root = fakeSys(t, "wlp1", "devices/pci0000:00/0000:00:1c.0/net/wlp1",
		map[string]string{"type": "1\n", "wireless/x": "", "device/uevent": "DRIVER=iwlwifi\nPCI_ID=1\n"}, nil)
	if i := ClassifyIface(root, "wlp1"); i.Type != "wlan" || i.Bus != "" || i.Driver != "iwlwifi" {
		t.Fatalf("%+v", i)
	}
	// virtual device
	root = fakeSys(t, "wg0", "devices/virtual/net/wg0", nil, nil)
	if i := ClassifyIface(root, "wg0"); !i.Virtual || i.Type != "virtual" {
		t.Fatalf("%+v", i)
	}
	// nothing readable: unknown, no bus
	if i := ClassifyIface(t.TempDir(), "eth9"); i.Type != "unknown" || i.Bus != "" {
		t.Fatalf("%+v", i)
	}
	if i := ClassifyIface(root, "../x"); i.Type != "unknown" {
		t.Fatalf("%+v", i)
	}
}

func TestIfaceWatch(t *testing.T) {
	w := newIfaceWatch([]string{"lo", "eth0"})
	if _, ok := w.Link("eth0", IfaceInfo{Type: "ethernet"}); ok {
		t.Fatal("present at start")
	}
	if _, ok := w.Link("wg0", IfaceInfo{Type: "virtual", Virtual: true}); ok {
		t.Fatal("virtual")
	}
	usb := IfaceInfo{Type: "ethernet", Bus: "usb", Driver: "rndis_host"}
	ev, ok := w.Link("usb0", usb)
	if !ok || ev.Kind != KindNewIface || ev.Severity != SevMedium || ev.Detail != "new interface type=ethernet bus=usb driver=rndis_host" {
		t.Fatalf("%+v %v", ev, ok)
	}
	if _, ok := w.Link("usb0", usb); ok {
		t.Fatal("once")
	}
	ev, ok = w.DefaultRoute("usb0", usb)
	if !ok || ev.Severity != SevHigh {
		t.Fatalf("%+v", ev)
	}
	if _, ok := w.DefaultRoute("eth0", usb); ok {
		t.Fatal("old interface")
	}
	if ev, _ := w.Link("eth5", IfaceInfo{Type: "unknown"}); ev.Severity != SevLow || ev.Detail != "new interface type=unknown" {
		t.Fatalf("%+v", ev)
	}
}
