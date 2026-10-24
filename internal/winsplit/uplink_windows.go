package winsplit

import (
	"errors"
	"net/netip"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Uplink is the real network the machine is connected through (not our own
// adapter, not another VPN).
type Uplink struct {
	Index   uint32 // interface index, what IP_UNICAST_IF wants
	Name    string
	Link    string // wifi | ethernet | mobile
	SSID    string // Wi-Fi name, "" if unknown
	Gateway string
	DNS     netip.Addr // first IPv4 DNS server the network hands out, invalid = none
}

// Key identifies the network for change detection.
func (u Uplink) Key() string { return u.Name + "|" + u.SSID + "|" + u.Gateway + "|" + u.DNS.String() }

const (
	ifTypeEthernet = 6
	ifTypeWiFi     = 71
	ifTypeWWAN1    = 243
	ifTypeWWAN2    = 244
)

// FindUplink returns the connected adapter with an IPv4 default gateway and
// the lowest metric (Windows' own pick), ignoring the Shunt adapter,
// tunnels and loopback. An error means: no connection right now.
func FindUplink() (Uplink, error) {
	var size uint32 = 16 << 10
	var buf []byte
	for range 4 {
		buf = make([]byte, size)
		err := windows.GetAdaptersAddresses(windows.AF_INET, windows.GAA_FLAG_INCLUDE_GATEWAYS|windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST,
			0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			return Uplink{}, err
		}
	}
	var best Uplink
	bestMetric := ^uint32(0)
	for a := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); a != nil; a = a.Next {
		name := windows.UTF16PtrToString(a.FriendlyName)
		if a.OperStatus != 1 || name == AdapterName || a.FirstGatewayAddress == nil {
			continue
		}
		var link string
		switch a.IfType {
		case ifTypeEthernet:
			link = "ethernet"
		case ifTypeWiFi:
			link = "wifi"
		case ifTypeWWAN1, ifTypeWWAN2:
			link = "mobile"
		default:
			continue // tunnels, PPP (other VPNs), loopback
		}
		if a.Ipv4Metric >= bestMetric {
			continue
		}
		bestMetric = a.Ipv4Metric
		best = Uplink{Index: a.IfIndex, Name: name, Link: link, Gateway: a.FirstGatewayAddress.Address.IP().String()}
		for d := a.FirstDnsServerAddress; d != nil; d = d.Next {
			if ip, ok := netip.AddrFromSlice(d.Address.IP()); ok && ip.Unmap().Is4() {
				best.DNS = ip.Unmap()
				break
			}
		}
	}
	if best.Index == 0 {
		return Uplink{}, errors.New("no network connection")
	}
	if best.Link == "wifi" {
		best.SSID = currentSSID()
	}
	return best, nil
}

// currentSSID reads the connected Wi-Fi name from netsh (the same text in
// every language: the line starts with "SSID").
func currentSSID() string {
	cmd := exec.Command("netsh", "wlan", "show", "interfaces")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return parseSSID(out)
}
