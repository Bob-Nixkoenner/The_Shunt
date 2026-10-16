package tsconf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func parse(t *testing.T, s string) (*Config, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "x.ts")
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
	return ParseFile(p)
}

func TestParse(t *testing.T) {
	c, err := parse(t, "# comment\nlogin_server = http://hs.example:8080 # c\nauth_key = hskey-1\nhostname = my-box\nexit_node = 100.64.0.1\n")
	if err != nil {
		t.Fatal(err)
	}
	if c.LoginServer != "http://hs.example:8080" || c.AuthKey != "hskey-1" || c.Hostname != "my-box" || c.ExitNode != "100.64.0.1" {
		t.Fatalf("%+v", c)
	}
	if _, ok := c.ExitNodeAddr(); !ok || c.Prefixes()[0].String() != "0.0.0.0/0" {
		t.Fatal("exit node should route everything")
	}
	c, _ = parse(t, "auth_key = k\n")
	if c.Prefixes()[0].String() != "100.64.0.0/10" {
		t.Fatal("no exit node: tailnet only")
	}
}

func TestRejects(t *testing.T) {
	for in, want := range map[string]string{
		"":                                       "auth_key missing",
		"auth_key = a b\n":                       "odd characters",
		"auth_key = k\nlogin_server = ftp://x\n": "login_server",
		"auth_key = k\nhostname = a;b\n":         "hostname",
		"auth_key = k\nexit_node = a b\n":        "exit_node",
		"auth_key = k\nfoo = 1\n":                "unknown key",
		"nonsense\n":                             "key = value",
	} {
		if _, err := parse(t, in); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want %q", in, err, want)
		}
	}
}
