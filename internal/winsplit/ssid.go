package winsplit

import (
	"bufio"
	"bytes"
	"strings"
)

// parseSSID reads the Wi-Fi name from `netsh wlan show interfaces` (the
// label is "SSID" in every language; "BSSID" lines are not it).
func parseSSID(out []byte) string {
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if rest, ok := strings.CutPrefix(line, "SSID"); ok {
			if _, v, ok := strings.Cut(rest, ":"); ok && !strings.HasPrefix(strings.TrimSpace(rest), "BSSID") {
				return strings.TrimSpace(v)
			}
		}
	}
	return ""
}
