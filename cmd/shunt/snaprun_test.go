package main

import "testing"

func TestIsAppExe(t *testing.T) {
	for exe, want := range map[string]bool{
		"/snap/brave/696/opt/brave.com/brave/brave":  true,
		"/snap/firefox/9057/usr/lib/firefox/firefox": true,
		"/usr/lib/snapd/snap-confine":                false,
		"/usr/lib/snapd/snap-exec":                   false,
		"/usr/bin/snap":                              false,
		"/snap/core/1/usr/lib/snapd/snap-confine":    false,
		"/snap/snapd/123/usr/bin/snap":               false,
		"/snap/bin/brave":                            false,
		"/usr/bin/google-chrome-stable":              false,
	} {
		if got := isAppExe(exe); got != want {
			t.Errorf("%s: %v", exe, got)
		}
	}
	if !snapApp([]string{"env", "BAMF=x", "/snap/bin/brave", "%U"}) || snapApp([]string{"/usr/bin/foo"}) || snapApp([]string{"env", "A=b"}) {
		t.Error("snapApp")
	}
}
