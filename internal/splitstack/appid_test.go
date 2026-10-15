package splitstack

import "testing"

func TestAppID(t *testing.T) {
	m := map[string]string{`c:\a\b.exe`: "x", "curl.exe": "y", "org.app": "z"}
	for app, want := range map[string]string{
		`c:\a\b.exe`: "x", `c:\other\curl.exe`: "y", "c:/other/curl.exe": "y", "org.app": "z", `c:\a\c.exe`: "", "": "",
	} {
		if got, _ := appRoute(m, app); got != want {
			t.Errorf("%q -> %q, want %q", app, got, want)
		}
	}
	if !appInSet(map[string]bool{"firefox.exe": true}, `c:\x\firefox.exe`) || appInSet(map[string]bool{"firefox.exe": true}, `c:\x\fire.exe`) {
		t.Error("appInSet")
	}
}
