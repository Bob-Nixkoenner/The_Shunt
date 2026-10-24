package splitstack

import (
	"net/netip"
	"testing"
)

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

func TestPinned(t *testing.T) {
	id := Pinned("tunnel:vps", `c:\b\brave.exe`)
	if r, app := splitPinned(id); r != "tunnel:vps" || app != `c:\b\brave.exe` {
		t.Fatalf("split %q: %q %q", id, r, app)
	}
	for _, id := range []string{`c:\b\brave.exe`, "run:", "run:>x", "org.app"} {
		if r, app := splitPinned(id); r != "" || app != id {
			t.Errorf("%q: pinned %q %q", id, r, app)
		}
	}
	e := &Engine{tunnels: map[string]*wgTunnel{"vps": {}}, apps: map[string]string{"brave.exe": "direct"}, def: "block"}
	dst := netip.MustParseAddrPort("1.2.3.4:443")
	for _, c := range []struct{ app, pinned, want string }{
		{`c:\b\brave.exe`, "", "direct"},               // app rule
		{`c:\b\brave.exe`, "tunnel:vps", "tunnel:vps"}, // started in a route: wins over the app rule
		{`c:\b\brave.exe`, "tunnel:gone", "block"},     // route gone: blocked, not the app rule
		{`c:\x\curl.exe`, "link:wifi", "link:wifi"},
		{`c:\x\curl.exe`, "", "block"}, // default
	} {
		if got, _ := e.routeFor(c.app, c.pinned, 6, dst, false); got != c.want {
			t.Errorf("%s pinned %q: %q, want %q", c.app, c.pinned, got, c.want)
		}
		if got, _ := e.routeFor(c.app, c.pinned, 17, dst, true); got != c.want { // DNS goes the same way
			t.Errorf("DNS %s pinned %q: %q, want %q", c.app, c.pinned, got, c.want)
		}
	}
}
