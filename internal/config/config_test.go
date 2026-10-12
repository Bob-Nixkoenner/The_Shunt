package config

import "testing"

const valid = `
[daemon]
default_route = "tunnel:vps"

[tunnel.vps]
config = "vps.conf"

[group.torrent]

[[rule]]
name = "ssh direct"
port = ["tcp/22"]
route = "direct"

[[rule]]
group = ["torrent"]
cidr = ["192.168.0.0/16", "fd00::/8", "10.0.0.1"]
port = ["udp/6881-6889"]
route = "block"
`

func TestParseValid(t *testing.T) {
	c, err := Parse(valid)
	if err != nil {
		t.Fatal(err)
	}
	if c.Tunnels["vps"].Interface != "sh-vps" || c.Tunnels["vps"].Driver != "auto" {
		t.Errorf("defaults not applied: %+v", c.Tunnels["vps"])
	}
	if got := len(c.Routes()); got != 3 {
		t.Errorf("routes: %d", got)
	}
}

func TestParseInvalid(t *testing.T) {
	for name, in := range map[string]string{
		"unknown key":    "[daemon]\nfoo = 1\n",
		"unknown tunnel": "[[rule]]\nport=[\"tcp/1\"]\nroute=\"tunnel:nope\"\n",
		"unknown group":  "[[rule]]\ngroup=[\"nope\"]\nroute=\"direct\"\n",
		"no selector":    "[[rule]]\nroute=\"direct\"\n",
		"bad port":       "[[rule]]\nport=[\"tcp/0\"]\nroute=\"direct\"\n",
		"bad range":      "[[rule]]\nport=[\"udp/9-1\"]\nroute=\"direct\"\n",
		"bad cidr":       "[[rule]]\ncidr=[\"300.1.1.1\"]\nroute=\"direct\"\n",
		"bad name":       "[tunnel.\"Bad_Name\"]\nconfig=\"x\"\n",
		"long name":      "[tunnel.abcdefghijk]\nconfig=\"x\"\n",
		"bad driver":     "[tunnel.a]\nconfig=\"x\"\ndriver=\"tap\"\n",
		"bad default":    "[daemon]\ndefault_route=\"somewhere\"\n",
	} {
		if _, err := Parse(in); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}
