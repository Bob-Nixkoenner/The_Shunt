package splitstack

import "testing"

func TestParseConfig(t *testing.T) {
	ok := `{"tunnels":[{"name":"a","conf":""}],"default":"tunnel:a","apps":{"10001":"direct","C:\\\\Apps\\\\firefox.exe":"block"}}`
	c, err := parseConfig(ok)
	if err != nil || c.DirectDNS != "1.1.1.1" || c.MTU != 1280 {
		t.Fatalf("%+v %v", c, err)
	}
	if c, _ := parseConfig(`{}`); c.Default != RouteBlock {
		t.Errorf("empty config must block by default, got %q", c.Default)
	}
	for _, bad := range []string{
		`{"default":"tunnel:x"}`,
		`{"apps":{"":"direct"}}`,
		`{"apps":{"1":"elsewhere"}}`,
		`{"tunnels":[{"name":"a"},{"name":"a"}]}`,
		`{"direct_dns":"dns.google"}`,
		`not json`,
	} {
		if _, err := parseConfig(bad); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}
