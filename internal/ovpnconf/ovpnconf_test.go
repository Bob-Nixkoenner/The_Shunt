package ovpnconf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const provider = `client
dev tun
proto udp
remote nl1.example.net 1194
remote nl2.example.net 443 tcp
resolv-retry infinite
nobind
persist-key
auth-user-pass
redirect-gateway def1
dhcp-option DNS 10.208.0.1
verb 3
<ca>
-----BEGIN CERTIFICATE-----
up /tmp/evil.sh
-----END CERTIFICATE-----
</ca>
<tls-crypt>
x
</tls-crypt>
`

func TestProviderConfig(t *testing.T) {
	c, err := Parse(provider, "")
	if err != nil {
		t.Fatal(err)
	}
	if !c.NeedsAuth || c.AuthFile != "" {
		t.Errorf("auth: %+v", c)
	}
	if len(c.Remotes) != 2 || c.Remotes[1] != "nl2.example.net 443 tcp" {
		t.Errorf("remotes: %q", c.Remotes)
	}
}

func TestForbidden(t *testing.T) {
	for _, l := range []string{
		"up /tmp/x.sh", "script-security 2", "plugin /lib/x.so", `"up" x`, "--up x",
		"log /etc/passwd", "management 127.0.0.1 7505", "user nobody", "UP x",
		"<plugin>\nx\n</plugin>", "engine /tmp/x.so", "providers legacy /tmp/x", "providers ../x", "pkcs11-providers /tmp/p11.so",
		"tls-export-cert /tmp",
	} {
		_, err := Parse("client\nremote a.example 1194\n"+l+"\n", "")
		if err == nil || !strings.Contains(err.Error(), "not allowed") {
			t.Errorf("%q: %v", l, err)
		}
	}
}

func TestProvidersByName(t *testing.T) {
	if _, err := Parse("client\nremote a.example 1194\nproviders legacy default\n", ""); err != nil {
		t.Fatalf("named OpenSSL providers refused: %v", err)
	}
}

func TestSanitize(t *testing.T) {
	in := "client\nremote a.example 1194\nscript-security 2\nup /etc/openvpn/update-resolv-conf\ndown /etc/openvpn/update-resolv-conf\n<plugin>\nx\n</plugin>\n<ca>\nup inside a cert\n</ca>\n"
	out, removed := Sanitize(in)
	if len(removed) != 4 {
		t.Errorf("removed: %q", removed)
	}
	if _, err := Parse(out, ""); err != nil {
		t.Fatalf("sanitized config refused: %v\n%s", err, out)
	}
	if !strings.Contains(out, "up inside a cert") || strings.Contains(out, "<plugin>") {
		t.Errorf("wrong cut:\n%s", out)
	}
	if out, _ := Sanitize("server 10.208.0.0 255.255.255.0\nremote a 1\n"); !strings.Contains(out, "\nremote") {
		t.Error("server line handling")
	} else if _, err := Parse(out, ""); err == nil {
		t.Error("server config accepted after sanitize")
	}
}

func TestInlineAuthAndFiles(t *testing.T) {
	c, err := Parse("remote a 1\nauth-user-pass\n<auth-user-pass>\nu\np\n</auth-user-pass>\n", "")
	if err != nil || c.NeedsAuth {
		t.Fatalf("%v %+v", err, c)
	}
	if _, err := Parse("remote a 1\nca ca.crt\n", ""); err == nil {
		t.Error("separate file accepted on import")
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "ca.crt"), []byte("x"), 0o600)
	os.WriteFile(filepath.Join(dir, "pass"), []byte("u\np\n"), 0o600)
	c, err = Parse("remote a 1\nca ca.crt # comment\nauth-user-pass pass\n", dir)
	if err != nil {
		t.Fatal(err)
	}
	if c.NeedsAuth || len(c.Files) != 2 {
		t.Errorf("%+v", c)
	}
	if _, err := Parse("remote a 1\nca missing.crt\n", dir); err == nil {
		t.Error("missing file accepted")
	}
}

func TestNoRemote(t *testing.T) {
	if _, err := Parse("[Interface]\nPrivateKey = x\n", ""); err == nil {
		t.Error("WireGuard file accepted as OpenVPN")
	}
}

func TestFields(t *testing.T) {
	got := fields(`remote "a b" 1194 # c`)
	if len(got) != 3 || got[1] != "a b" {
		t.Errorf("%q", got)
	}
}

func FuzzParse(f *testing.F) {
	f.Add(provider)
	f.Fuzz(func(t *testing.T, s string) { _, _ = Parse(s, "") })
}

// H-01 (external report, 13.11.): openvpn ends an inline block at a line that
// starts with the close tag and reads the next lines as options; Shunt waited
// for the exact tag and took them for block content. A byte order mark in
// front of a directive hid it from Shunt but not from openvpn.
func TestParserParityWithOpenVPN(t *testing.T) {
	base := "client\nremote vpn.example 1194\n"
	bad := map[string]string{
		"text after close tag":   base + "<ca>\nAAAA\n</ca>x\nplugin /tmp/x.so\n",
		"comment after close":    base + "<ca>\nAAAA\n</ca> # note\nup /tmp/x\n",
		"bom before directive":   "\ufeffplugin /tmp/x.so\n" + base,
		"bom inside the file":    base + "\ufeff up /tmp/x\n",
		"backslash in the name":  base + "plug\\in /tmp/x.so\n",
		"quoted odd name":        base + "\"plugin\u00a0\" /tmp/x.so\n",
		"upper case close, then": base + "<ca>\nAAAA\n</CA>\n</ca>\n",
	}
	for name, conf := range bad {
		if _, err := Parse(conf, ""); err == nil {
			t.Errorf("%s: accepted", name)
		}
		clean, removed := Sanitize(conf)
		if len(removed) == 0 {
			t.Errorf("%s: Sanitize removed nothing", name)
		}
		if strings.Contains(clean, "plugin /tmp") && !strings.Contains(clean, "# removed") {
			t.Errorf("%s: plugin line left active:\n%s", name, clean)
		}
	}
	// what Sanitize leaves must pass Parse (the import path runs both)
	for name, conf := range bad {
		clean, _ := Sanitize(conf)
		if name == "upper case close, then" {
			continue // a stray close tag stays refused
		}
		if _, err := Parse(clean, ""); err != nil {
			t.Errorf("%s: sanitized text still refused: %v", name, err)
		}
	}
	// an honest file with inline blocks and a BOM at the start still works
	ok := "\ufeffclient\nremote vpn.example 1194 udp\n<ca>\nAAAA\n</ca>\n<tls-crypt>\nBBBB\n</tls-crypt>\n"
	if c, err := Parse(ok, ""); err != nil || len(c.Remotes) != 1 {
		t.Fatalf("honest file: %v %+v", err, c)
	}
}
