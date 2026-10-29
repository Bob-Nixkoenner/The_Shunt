package config

import (
	"strings"
	"testing"
)

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
	if got := len(c.Routes()); got != 3+len(LinkKinds) {
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
		"bad lockdown":   "[daemon]\nboot_lockdown=\"yes\"\n",
		"bad timestamps": "[daemon]\ntcp_timestamps=\"no\"\n",
		"auth on wg":     "[tunnel.a]\nconfig=\"x\"\nauth=\"p\"\n",
		"via direct":     "[tunnel.a]\nconfig=\"x\"\nvia=\"direct\"\n",
		"via self":       "[tunnel.a]\nconfig=\"x\"\nvia=\"tunnel:a\"\n",
		"net no crit":    "[[network]]\nname=\"x\"\ndefault_route=\"direct\"\n",
		"net bad mac":    "[[network]]\nname=\"x\"\ngateway_mac=[\"zz\"]\ndefault_route=\"direct\"\n",
		"net bad route":  "[[network]]\nname=\"x\"\nssid=[\"a\"]\ndefault_route=\"tunnel:nope\"\n",
		"net dup":        "[[network]]\nname=\"x\"\nssid=[\"a\"]\ndefault_route=\"direct\"\n[[network]]\nname=\"x\"\nssid=[\"b\"]\ndefault_route=\"direct\"\n",
		"bad fw mode":    "[firewall]\nmode=\"maybe\"\n",
		"bad net fw":     "[[network]]\nname=\"x\"\nssid=[\"a\"]\ndefault_route=\"direct\"\nfirewall=\"x\"\n",
		"via loop":       "[tunnel.a]\nconfig=\"x\"\nvia=\"tunnel:b\"\n[tunnel.b]\nconfig=\"y\"\nvia=\"tunnel:a\"\n",
	} {
		if _, err := Parse(in); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestHopsAndOpenVPN(t *testing.T) {
	c, err := Parse("[tunnel.a]\nconfig=\"a.ovpn\"\ndriver=\"openvpn\"\nauth=\"a.auth\"\n[tunnel.b]\nconfig=\"b.conf\"\nvia=\"tunnel:a\"\n")
	if err != nil {
		t.Fatal(err)
	}
	if !c.Tunnels["a"].IsOpenVPN() || c.Tunnels["b"].Via != "tunnel:a" {
		t.Errorf("%+v", c.Tunnels)
	}
}

func TestMatchNetwork(t *testing.T) {
	c, err := Parse(`
[[network]]
name = "home"
ssid = ["FritzBox"]
gateway_mac = ["AA:BB:CC:DD:EE:FF"]
default_route = "direct"

[[network]]
name = "office"
ssid = ["Corp", "Corp-5G"]
default_route = "block"
`)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ ssid, mac, want string }{
		{"FritzBox", "aa:bb:cc:dd:ee:ff", "home"},
		{"FritzBox", "11:22:33:44:55:66", ""}, // faked SSID
		{"FritzBox", "", ""},                  // gateway unknown: not trusted
		{"", "aa:bb:cc:dd:ee:ff", ""},         // wired, same router: SSID required
		{"Corp-5G", "", "office"},
		{"corp", "", ""},
	} {
		got := ""
		if n := c.MatchNetwork(tc.ssid, tc.mac); n != nil {
			got = n.Name
		}
		if got != tc.want {
			t.Errorf("%q %q: %q, want %q", tc.ssid, tc.mac, got, tc.want)
		}
	}
}

func TestEncodeRoundTrip(t *testing.T) {
	c, err := Parse(valid)
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Encode()
	if err != nil {
		t.Fatal(err)
	}
	c2, err := Parse(string(b))
	if err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	if len(c2.Rules) != len(c.Rules) || c2.Rules[1].CIDR[2] != "10.0.0.1" || c2.Daemon.DefaultRoute != "tunnel:vps" {
		t.Fatalf("round trip lost data:\n%s", b)
	}
	for _, unwanted := range []string{"interface", "driver", "socket ="} {
		if strings.Contains(string(b), unwanted) {
			t.Errorf("default %q written:\n%s", unwanted, b)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add(valid)
	f.Add("[[rule]]\napp=[\"firefox\"]\nargs=[\"-P sm\"]\nroute=\"block\"\n")
	f.Add("[dns.upstream.x]\naddr=\"https://1.1.1.1/dns-query\"\ntls_name=\"one\"\n")
	f.Fuzz(func(t *testing.T, s string) {
		c, err := Parse(s)
		if err != nil {
			return
		}
		// whatever is accepted must survive an encode/parse round trip
		b, err := c.Encode()
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		if _, err := Parse(string(b)); err != nil {
			t.Fatalf("round trip of accepted config failed: %v\n%s", err, b)
		}
	})
}

func TestFirewallMode(t *testing.T) {
	c, err := Parse("[firewall]\nmode = \"ask\"\n[[network]]\nname = \"home\"\nssid = [\"h\"]\ndefault_route = \"direct\"\nfirewall = \"off\"\n")
	if err != nil {
		t.Fatal(err)
	}
	if c.FirewallMode("") != "ask" || c.FirewallMode("home") != "off" || c.FirewallTimeout() != 30 {
		t.Errorf("%s %s %d", c.FirewallMode(""), c.FirewallMode("home"), c.FirewallTimeout())
	}
	c, _ = Parse("")
	if c.FirewallMode("") != "off" {
		t.Error("default not off")
	}
}

func TestBootLockdown(t *testing.T) {
	const tun = "[tunnel.vps]\nconfig=\"x\"\n"
	for in, want := range map[string]bool{
		"": false,
		"[daemon]\ndefault_route=\"link:wifi\"\n":                                        false,
		"[daemon]\ndefault_route=\"block\"\n":                                            true,
		tun + "[daemon]\ndefault_route=\"tunnel:vps\"\n":                                 true,
		tun + "[daemon]\ndefault_route=\"tunnel:vps\"\nboot_lockdown=\"off\"\n":          false,
		"[daemon]\nboot_lockdown=\"on\"\n":                                               true,
		tun + "[[network]]\nname=\"cafe\"\nssid=[\"c\"]\ndefault_route=\"tunnel:vps\"\n": true,
	} {
		c, err := Parse(in)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if got := c.BootLockdownOn(); got != want {
			t.Errorf("%q: got %v", in, got)
		}
	}
}

func TestLinkRoutes(t *testing.T) {
	c := &Config{}
	r, err := c.ParseRoute("link:wifi")
	if err != nil || r.Kind != RouteLink || r.String() != "link:wifi" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := c.ParseRoute("link:carrier-pigeon"); err == nil {
		t.Error("unknown connection kind accepted")
	}
}

func TestDNSFilterConfig(t *testing.T) {
	base := "[tunnel.vps]\nconfig = \"vps.conf\"\n"
	for _, bad := range []string{
		"[dns_filter]\ndefault = \"strict\"\n",
		"[dns_filter]\nnormal = [\"../etc/passwd\"]\n",
		"[dns_filter]\nnormal = [\"http://example.com/list\"]\n",
		"[dns_filter]\nsource = \"http://example.com/\"\n",
		"[dns_filter]\nallow = [\"a b\"]\n",
		"[tunnel.x]\nconfig = \"x.conf\"\ndns_filter = \"max\"\n",
		"[[rule]]\ncidr = [\"10.0.0.0/8\"]\nroute = \"direct\"\ndns_filter = \"low\"\n",
		"[[rule]]\napp = [\"firefox\"]\n",
		"[[rule]]\ngroup = [\"g\"]\nport = [\"tcp/443\"]\ndns_filter = \"low\"\n[group.g]\n",
	} {
		if _, err := Parse(base + bad); err == nil {
			t.Errorf("accepted:\n%s", bad)
		}
	}
	c, err := Parse(base + `
[[network]]
name = "work"
ssid = ["corp"]
default_route = "direct"
dns_filter = "paranoid"
[[rule]]
app = ["firefox"]
dns_filter = "low"
`)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.UsedFilterLevels(); strings.Join(got, ",") != "low,normal,paranoid" {
		t.Errorf("used levels %v", got)
	}
	f := c.Filter()
	if f.Default != FilterNormal || !strings.HasPrefix(strings.Join(f.Lists(FilterNormal), ","), "hagezi:light,hagezi:tif.mini,Phishing-Angriffe,malware,") {
		t.Errorf("defaults %+v", f)
	}
	if u := f.ListURL("easylist"); u != DefaultFilterSource+"easylist" {
		t.Errorf("url %s", u)
	}
	if u := f.ListURL("hagezi:tif.mini"); u != "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.mini.txt" {
		t.Errorf("hagezi url %s", u)
	}
}
