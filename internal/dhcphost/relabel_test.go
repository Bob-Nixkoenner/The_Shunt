//go:build linux

package dhcphost

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// restorecon is stubbed: it prints a line when it "relabels" and records
// that it ran. relabel only acts on its own directory and only when
// restorecon exists.
func TestRelabel(t *testing.T) {
	dir := t.TempDir()
	oldF, oldD, oldL := defaultsFile, relabelDir, lookPath
	t.Cleanup(func() { defaultsFile, relabelDir, lookPath = oldF, oldD, oldL })
	relabelDir = filepath.Join(dir, "NetworkManager")
	defaultsFile = filepath.Join(relabelDir, "conf.d", "95-x.conf")
	ran := filepath.Join(dir, "ran")
	stub := filepath.Join(dir, "restorecon")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\necho \"$@\" > "+ran+"\necho Relabeled x\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	lookPath = func(string) (string, error) { return stub, nil }
	if !relabel(context.Background()) {
		t.Fatal("restorecon changed a label: relabel must say so")
	}
	if b, _ := os.ReadFile(ran); string(b) != "-Rv "+relabelDir+"\n" {
		t.Fatalf("restorecon ran with %q", b)
	}
	os.Remove(ran)
	// a foreign directory is left alone
	defaultsFile = filepath.Join(dir, "other", "conf.d", "95-x.conf")
	if relabel(context.Background()) {
		t.Fatal("relabel touched a directory that is not NetworkManager's")
	}
	if _, err := os.Stat(ran); err == nil {
		t.Fatal("restorecon ran for a foreign directory")
	}
	// no restorecon (no SELinux): nothing happens
	defaultsFile = filepath.Join(relabelDir, "conf.d", "95-x.conf")
	lookPath = func(string) (string, error) { return "", os.ErrNotExist }
	if relabel(context.Background()) {
		t.Fatal("relabel without restorecon must do nothing")
	}
}
