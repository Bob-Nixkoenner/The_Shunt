//go:build windows

package winsplit

import (
	"net"
	"os/exec"
	"strings"
)

// SetWifiRandomMAC switches Windows' random hardware addresses for every
// Wi-Fi interface on or off and returns how many interfaces accepted it.
// netsh fails for adapters that are not Wi-Fi (ignored); the interface names
// come from the network stack, so this does not depend on the Windows
// language. Wi-Fi drivers without support ignore it (Windows limit).
func SetWifiRandomMAC(on bool) int {
	ifs, _ := net.Interfaces()
	n := 0
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 || len(i.HardwareAddr) == 0 || i.Name == AdapterName {
			continue
		}
		out, err := exec.Command("netsh", WifiRandomizationArgs(i.Name, on)...).CombinedOutput()
		if err == nil && !strings.Contains(strings.ToLower(string(out)), "not found") {
			n++
		}
	}
	return n
}
