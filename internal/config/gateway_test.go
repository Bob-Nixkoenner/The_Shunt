package config

import (
	"strings"
	"testing"
)

func TestGatewayValidate(t *testing.T) {
	const head = "[tunnel.a]\nconfig = \"a.conf\"\n[tunnel.t]\ndriver = \"tor\"\n[gateway]\nenabled = true\n"
	cases := []struct{ name, body, want string }{
		{"ok", "[[gateway.group]]\nname = \"vms\"\ninterfaces = [\"virbr1\"]\nroute = \"tunnel:a\"\n", ""},
		{"no route = block", "[[gateway.group]]\nname = \"vms\"\ninterfaces = [\"virbr1\"]\n", ""},
		{"no interfaces", "[[gateway.group]]\nname = \"vms\"\n", "interfaces missing"},
		{"loopback", "[[gateway.group]]\nname = \"vms\"\ninterfaces = [\"lo\"]\n", "invalid interface"},
		{"injection", "[[gateway.group]]\nname = \"vms\"\ninterfaces = [\"a\\\" drop\"]\n", "invalid interface"},
		{"twice", "[[gateway.group]]\nname = \"a\"\ninterfaces = [\"br0\"]\n[[gateway.group]]\nname = \"b\"\ninterfaces = [\"br0\"]\n", "another group"},
		{"same name", "[[gateway.group]]\nname = \"a\"\ninterfaces = [\"br0\"]\n[[gateway.group]]\nname = \"a\"\ninterfaces = [\"br1\"]\n", "used twice"},
		{"tunnel iface", "[[gateway.group]]\nname = \"a\"\ninterfaces = [\"sh-a\"]\n", "interface of tunnel"},
		{"unknown route", "[[gateway.group]]\nname = \"a\"\ninterfaces = [\"br0\"]\nroute = \"tunnel:zz\"\n", "unknown tunnel"},
		{"tor route", "[[gateway.group]]\nname = \"a\"\ninterfaces = [\"br0\"]\nroute = \"tunnel:t\"\n", "Tor tunnel"},
		{"ipv6 pass", "ipv6 = \"pass\"\n[[gateway.group]]\nname = \"a\"\ninterfaces = [\"br0\"]\n", "not implemented"},
	}
	for _, c := range cases {
		body := c.body
		if strings.HasPrefix(body, "ipv6") { // key belongs under [gateway]
			_, err := Parse(head + body)
			expect(t, c.name, err, c.want)
			continue
		}
		_, err := Parse(head + body)
		expect(t, c.name, err, c.want)
	}
}

func expect(t *testing.T, name string, err error, want string) {
	t.Helper()
	switch {
	case want == "" && err != nil:
		t.Errorf("%s: %v", name, err)
	case want != "" && (err == nil || !strings.Contains(err.Error(), want)):
		t.Errorf("%s: got %v, want error with %q", name, err, want)
	}
}

func TestGatewayOff(t *testing.T) {
	c, err := Parse("[gateway]\nenabled = false\n[[gateway.group]]\nname = \"a\"\ninterfaces = [\"br0\"]\n")
	if err != nil || c.GatewayOn() {
		t.Fatalf("err %v on %v", err, c.GatewayOn())
	}
	if c, _ = Parse(""); c.GatewayOn() {
		t.Error("on by default")
	}
}
