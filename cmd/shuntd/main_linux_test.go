package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/daemon"
)

// The installer's dry run (`shuntd check`) failed with "unsafe identifier"
// when the update was started from the autostarted desktop app, whose cgroup
// path has a backslash (app-the\x2dshunt@autostart.service).
func TestCheckIgnoresCallersCgroup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shunt.toml")
	if err := os.WriteFile(path, []byte("[daemon]\nsocket = \"/nonexistent/s.sock\"\n[dns]\ndirect = \"cloudflare\"\n[dns.upstream.cloudflare]\naddr = \"1.1.1.1\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := daemon.Prepare(path, `user.slice/app.slice/app-the\x2dshunt@autostart.service/daemon`); err == nil {
		t.Fatal("a cgroup path with a backslash must stay refused by the ruleset")
	}
	if _, err := daemon.Prepare(path, checkCgroupRoot); err != nil {
		t.Fatalf("check root rejected: %v", err)
	}
}
