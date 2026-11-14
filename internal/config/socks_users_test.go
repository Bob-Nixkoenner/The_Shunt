package config

import (
	"strings"
	"testing"
)

func TestSocksUsers(t *testing.T) {
	ok := "[tunnel.vps]\nconfig = \"vps.conf\"\nsocks = \"127.0.0.1:1080\"\nsocks_users = [\"1000\", \"user-a\"]\n"
	c, err := Parse(ok)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Tunnels["vps"].SocksUsers; len(got) != 2 || got[1] != "user-a" {
		t.Fatalf("socks_users = %v", got)
	}
	for in, want := range map[string]string{
		"[tunnel.vps]\nconfig = \"vps.conf\"\nsocks_users = [\"1000\"]\n":                                   "needs socks",
		"[tunnel.vps]\nconfig = \"vps.conf\"\nsocks = \"127.0.0.1:1080\"\nsocks_users = [\"\"]\n":           "bad user",
		"[tunnel.vps]\nconfig = \"vps.conf\"\nsocks = \"127.0.0.1:1080\"\nsocks_users = [\"a } accept\"]\n": "bad user",
	} {
		if _, err := Parse(in); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err %v, want %q", in, err, want)
		}
	}
}
