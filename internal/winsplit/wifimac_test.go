package winsplit

import (
	"reflect"
	"testing"
)

func TestWifiRandomizationArgs(t *testing.T) {
	got := WifiRandomizationArgs("Wi-Fi", true)
	want := []string{"wlan", "set", "randomization", "enabled=yes", "interface=Wi-Fi"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v", got)
	}
	if WifiRandomizationArgs("WLAN", false)[3] != "enabled=no" {
		t.Error("off")
	}
}
