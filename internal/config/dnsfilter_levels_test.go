package config

import (
	"slices"
	"testing"
)

func TestFilterLevelsBuildOnEachOther(t *testing.T) {
	f := DNSFilter{Low: []string{"a"}, Normal: []string{"b", "a"}, Paranoid: []string{"c"}}
	if got := f.Lists(FilterLow); !slices.Equal(got, []string{"a"}) {
		t.Fatalf("low: %v", got)
	}
	if got := f.Lists(FilterNormal); !slices.Equal(got, []string{"a", "b"}) {
		t.Fatalf("normal: %v", got)
	}
	if got := f.Lists(FilterParanoid); !slices.Equal(got, []string{"a", "b", "c"}) {
		t.Fatalf("paranoid: %v", got)
	}
	if f.Lists(FilterOff) != nil {
		t.Fatal("off has no lists")
	}
}
