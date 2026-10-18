package config

import "testing"

func TestDefaultFilterPerOS(t *testing.T) {
	has := func(l []string, n string) bool {
		for _, x := range l {
			if x == n {
				return true
			}
		}
		return false
	}
	win := defaultDNSFilterFor("windows")
	if !has(win.Lists(FilterNormal), "Win10Telemetry") || !has(win.Lists(FilterNormal), "MS-Office-Telemetry") {
		t.Error("Windows: telemetry lists belong in normal")
	}
	for _, os := range []string{"linux", "android", "darwin"} {
		f := defaultDNSFilterFor(os)
		for _, n := range []string{"Win10Telemetry", "MS-Office-Telemetry"} {
			if has(f.Lists(FilterParanoid), n) {
				t.Errorf("%s: %s must not be in any default", os, n)
			}
		}
	}
	for _, os := range []string{"windows", "linux"} {
		f := defaultDNSFilterFor(os)
		for _, n := range []string{"samsung", "lg-tv"} {
			if has(f.Lists(FilterParanoid), n) {
				t.Errorf("%s: phone/TV list %s in the defaults", os, n)
			}
		}
	}
}
