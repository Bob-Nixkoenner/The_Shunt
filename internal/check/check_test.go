package check

import (
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/Bob-Nixkoenner/the_shunt/internal/i18n"
	"github.com/Bob-Nixkoenner/the_shunt/internal/ovpnconf"
)

// allIDs is every finding the package can make; worstCase must trigger each.
var allIDs = []string{"dns.off", "dns.doh", "killswitch.off", "bootlock.off", "default.direct",
	"network.ssid_only", "stealth.unset", "inbound.off", "gateway.direct", "gateway.noroute", "gateway.bootlock",
	"ovpn.cipher", "ovpn.cbc", "ovpn.auth", "ovpn.compress", "ovpn.nowrap", "ovpn.tls", "ovpn.nocerttype",
	"rule.direct"}

func parse(t *testing.T, s string) *config.Config {
	t.Helper()
	c, err := config.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func ids(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.ID)
	}
	return out
}

func TestWorstCase(t *testing.T) {
	c := parse(t, `
[daemon]
default_route = "direct"
boot_lockdown = "off"
kill_switch = false
[dns]
disabled = true
allow_doh = true
[tunnel.a]
config = "a.ovpn"
driver = "openvpn"
[[network]]
name = "cafe"
ssid = ["Cafe"]
default_route = "direct"
`)
	weak := &ovpnconf.Config{Ciphers: []string{"BF-CBC"}, Auth: "SHA1", Compress: true, TLSVersionMin: "1.0"}
	cbc := &ovpnconf.Config{Ciphers: []string{"AES-256-CBC"}}
	seen := map[string]bool{}
	// Linux sees everything but the kill switch; Windows adds that one
	for _, env := range []Env{{OVPN: func(string) *ovpnconf.Config { return weak }}, {Windows: true}} {
		for _, f := range Config(c, env) {
			seen[f.ID] = true
		}
	}
	// default_route direct hides bootlock.off: use a tunnel default for it
	c2 := parse(t, "[daemon]\ndefault_route = \"tunnel:a\"\nboot_lockdown = \"off\"\n[tunnel.a]\nconfig = \"a.conf\"\n[gateway]\nenabled = true\n[[gateway.group]]\nname = \"x\"\ninterfaces = [\"br1\"]\n[[gateway.group]]\nname = \"y\"\ninterfaces = [\"br2\"]\nroute = \"direct\"\n")
	for _, f := range Config(c2, Env{}) {
		seen[f.ID] = true
	}
	for _, f := range OpenVPN("a", cbc) {
		seen[f.ID] = true
	}
	for _, f := range Config(parse(t, strictCfg), Env{}) {
		seen[f.ID] = true
	}
	for _, id := range allIDs {
		if !seen[id] {
			t.Errorf("finding %q never produced", id)
		}
	}
	for id := range seen {
		if !slices.Contains(allIDs, id) {
			t.Errorf("finding %q missing from allIDs", id)
		}
	}
}

func TestCleanConfigIsQuiet(t *testing.T) {
	c := parse(t, `
[daemon]
default_route = "tunnel:a"
mac = "stable"
dhcp_hostname = "none"
[tunnel.a]
config = "a.conf"
[inbound]
enabled = true
`)
	if got := Config(c, Env{}); len(got) != 0 {
		t.Errorf("clean config has findings: %v", ids(got))
	}
	good := &ovpnconf.Config{Ciphers: []string{"AES-256-GCM", "CHACHA20-POLY1305"}, Auth: "SHA256", TLSWrap: true, TLSVersionMin: "1.2", RemoteCertTLS: true}
	if got := OpenVPN("a", good); len(got) != 0 {
		t.Errorf("good OpenVPN file has findings: %v", ids(got))
	}
}

func TestSortedWorstFirst(t *testing.T) {
	c := parse(t, "[daemon]\ndefault_route = \"direct\"\n[dns]\ndisabled = true\n[tunnel.a]\nconfig = \"a.conf\"\n")
	fs := Config(c, Env{})
	if len(fs) < 2 || fs[0].Level != Bad || fs[len(fs)-1].Level != Info {
		t.Errorf("order: %v", fs)
	}
}

// Every message has a German text (Android and the tray translate the same
// sentence with their own catalog, so the catalog must have it).
func TestGerman(t *testing.T) {
	de := i18n.Dict("de")
	c := parse(t, `
[daemon]
default_route = "direct"
boot_lockdown = "off"
kill_switch = false
[dns]
disabled = true
allow_doh = true
[tunnel.a]
config = "a.ovpn"
driver = "openvpn"
[[network]]
name = "cafe"
ssid = ["Cafe"]
default_route = "direct"
`)
	weak := &ovpnconf.Config{Ciphers: []string{"BF-CBC"}, Auth: "SHA1", Compress: true, TLSVersionMin: "1.0"}
	all := append(Config(c, Env{Windows: true, OVPN: func(string) *ovpnconf.Config { return weak }}), Config(c, Env{OVPN: func(string) *ovpnconf.Config { return weak }})...)
	all = append(all, OpenVPN("a", &ovpnconf.Config{Ciphers: []string{"AES-256-CBC"}})...)
	all = append(all, Config(parse(t, "[daemon]\ndefault_route = \"tunnel:a\"\nboot_lockdown = \"off\"\n[tunnel.a]\nconfig = \"a.conf\"\n[gateway]\nenabled = true\n[[gateway.group]]\nname = \"x\"\ninterfaces = [\"br1\"]\n[[gateway.group]]\nname = \"y\"\ninterfaces = [\"br2\"]\nroute = \"direct\"\n"), Env{})...)
	all = append(all, Config(parse(t, strictCfg), Env{})...)
	for _, f := range all {
		if _, ok := de[f.Msg]; !ok {
			t.Errorf("no German for %q", f.Msg)
		}
	}
}

func TestHelpTLSWrap(t *testing.T) {
	fs := OpenVPN("x", &ovpnconf.Config{})
	for _, f := range fs {
		if f.ID == "ovpn.nowrap" {
			if f.Help == "" {
				t.Fatal("no help text")
			}
			return
		}
	}
	t.Fatal("no ovpn.nowrap finding")
}

// strictCfg: the hints the strict check cares about (no tls-crypt, DoH
// allowed, everything else direct, a direct rule) with the mode left open.
const strictCfg = `
[daemon]
default_route = "direct"
mac = "stable"
dhcp_hostname = "none"
config_check = "strict"
[dns]
allow_doh = true
[tunnel.a]
config = "a.ovpn"
driver = "openvpn"
[inbound]
enabled = true
[[rule]]
name = "printer"
cidr = ["192.168.1.20/32"]
route = "direct"
[[rule]]
app = ["firefox"]
route = "tunnel:a"
`

func levels(fs []Finding) map[string]string {
	m := map[string]string{}
	for _, f := range fs {
		m[f.ID] = f.Level
	}
	return m
}

// Normal mode: the hints stay quiet notes, nothing is "bad", no rule finding.
func TestCheckNormalMode(t *testing.T) {
	for _, mode := range []string{"", "normal"} {
		c := parse(t, strings.Replace(strictCfg, `config_check = "strict"`, `config_check = "`+mode+`"`, 1))
		env := Env{OVPN: func(string) *ovpnconf.Config {
			return &ovpnconf.Config{Ciphers: []string{"AES-256-GCM"}, RemoteCertTLS: true}
		}}
		fs := Config(c, env)
		got := levels(fs)
		want := map[string]string{"ovpn.nowrap": Warn, "dns.doh": Warn, "default.direct": Info}
		if !maps.Equal(got, want) {
			t.Errorf("mode %q: %v, want %v", mode, got, want)
		}
		for _, f := range fs {
			if f.Strict {
				t.Errorf("mode %q: %s marked strict", mode, f.ID)
			}
		}
	}
}

// Strict mode: the same hints are "bad" (shunt check fails), the direct rule
// is a finding of its own, everything is marked strict and sorted worst first.
func TestCheckStrictMode(t *testing.T) {
	c := parse(t, strictCfg)
	env := Env{OVPN: func(string) *ovpnconf.Config {
		return &ovpnconf.Config{Ciphers: []string{"AES-256-GCM"}, RemoteCertTLS: true}
	}}
	fs := Config(c, env)
	got := levels(fs)
	want := map[string]string{"ovpn.nowrap": Bad, "dns.doh": Bad, "default.direct": Bad, "rule.direct": Warn}
	if !maps.Equal(got, want) {
		t.Errorf("strict: %v, want %v", got, want)
	}
	for i, f := range fs {
		if !f.Strict {
			t.Errorf("%s not marked strict", f.ID)
		}
		if i > 0 && rank(fs[i-1].Level) > rank(f.Level) {
			t.Errorf("not sorted: %v", ids(fs))
		}
		if f.ID == "rule.direct" && f.Vals["rule"] != "printer" {
			t.Errorf("rule name: %v", f.Vals)
		}
	}
	// other findings go one level up: info → warn, warn → bad
	c2 := parse(t, "[daemon]\ndefault_route = \"tunnel:a\"\nconfig_check = \"strict\"\n[tunnel.a]\nconfig = \"a.ovpn\"\ndriver = \"openvpn\"\n")
	cbc := &ovpnconf.Config{Ciphers: []string{"AES-256-CBC"}, TLSWrap: true, RemoteCertTLS: true}
	got = levels(Config(c2, Env{OVPN: func(string) *ovpnconf.Config { return cbc }}))
	want = map[string]string{"ovpn.cbc": Bad, "stealth.unset": Warn, "inbound.off": Warn}
	if !maps.Equal(got, want) {
		t.Errorf("strict raise: %v, want %v", got, want)
	}
	// an unnamed direct rule is named by its place
	c3 := parse(t, "[daemon]\nconfig_check = \"strict\"\n[[rule]]\nport = [\"tcp/22\"]\nroute = \"direct\"\n")
	for _, f := range Config(c3, Env{Android: true}) {
		if f.ID == "rule.direct" && f.Vals["rule"] != "#1" {
			t.Errorf("unnamed rule: %v", f.Vals)
		}
	}
}
