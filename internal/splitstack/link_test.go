package splitstack

import "testing"

func TestResolveLink(t *testing.T) {
	e := &Engine{link: "wifi"}
	for route, want := range map[string][2]string{
		"link:wifi":     {RouteDirect, "wifi"},
		"link:ethernet": {RouteBlock, "ethernet"},
		"direct":        {RouteDirect, ""},
		"tunnel:x":      {"tunnel:x", ""},
	} {
		if r, k := e.resolveLink(route); r != want[0] || k != want[1] {
			t.Errorf("%s -> %s/%s, want %v", route, r, k, want)
		}
	}
	e.link = "" // unknown network: link routes block
	if r, _ := e.resolveLink("link:wifi"); r != RouteBlock {
		t.Errorf("unknown network: %s", r)
	}
	if err := CheckConfig(`{"default":"link:wifi","apps":{"a.exe":"link:mobile"}}`); err != nil {
		t.Error(err)
	}
	if err := CheckConfig(`{"default":"link:wired"}`); err == nil {
		t.Error("bad link kind accepted")
	}
}
