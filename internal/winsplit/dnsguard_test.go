package winsplit

import (
	"net/netip"
	"testing"
)

func TestGuardRanges(t *testing.T) {
	if got := guardRanges(netip.MustParseAddr("10.111.0.53")); got != "0.0.0.0-10.111.0.52,10.111.0.54-255.255.255.255" {
		t.Error(got)
	}
}
