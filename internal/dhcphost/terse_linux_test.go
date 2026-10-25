package dhcphost

import (
	"slices"
	"testing"
)

func TestSplitTerse(t *testing.T) {
	got := splitTerse(`0b5c:802-11-wireless:wlp2s0`)
	if !slices.Equal(got, []string{"0b5c", "802-11-wireless", "wlp2s0"}) {
		t.Errorf("%q", got)
	}
	if got := splitTerse(`a\:b:c:`); !slices.Equal(got, []string{"a:b", "c", ""}) {
		t.Errorf("%q", got)
	}
}
