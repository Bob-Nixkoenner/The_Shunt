package winsplit

import (
	"fmt"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procSendARP = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("SendARP")

// GatewayMAC returns the MAC address of the IPv4 gateway gw (lower case,
// colon separated), "" if unknown. The router answers from the ARP cache
// almost always; otherwise Windows asks with one ARP request (a few seconds
// at most when nobody answers).
func GatewayMAC(gw string) string {
	a, err := netip.ParseAddr(gw)
	if err != nil || !a.Is4() || procSendARP.Find() != nil {
		return ""
	}
	ip := a.As4()
	var mac [8]byte
	n := uint32(len(mac))
	r, _, _ := procSendARP.Call(uintptr(*(*uint32)(unsafe.Pointer(&ip[0]))), 0, uintptr(unsafe.Pointer(&mac[0])), uintptr(unsafe.Pointer(&n)))
	if r != 0 || n != 6 {
		return ""
	}
	return formatMAC(mac[:6])
}

func formatMAC(b []byte) string {
	if len(b) != 6 || (b[0]|b[1]|b[2]|b[3]|b[4]|b[5]) == 0 {
		return ""
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}
