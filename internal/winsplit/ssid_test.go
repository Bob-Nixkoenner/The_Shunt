package winsplit

import "testing"

func TestParseSSID(t *testing.T) {
	out := []byte("There is 1 interface on the system:\r\n\r\n    Name                   : WLAN\r\n    State                  : connected\r\n    SSID                   : Cafe_5G\r\n    BSSID                  : 02:00:00:00:00:01\r\n    Network type           : Infrastructure\r\n")
	if got := parseSSID(out); got != "Cafe_5G" {
		t.Fatalf("got %q", got)
	}
	if parseSSID([]byte("    BSSID : aa\r\n")) != "" {
		t.Fatal("BSSID taken for SSID")
	}
}
