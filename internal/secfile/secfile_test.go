package secfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWipe(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "x")
	if err := os.WriteFile(f, []byte("secret key material"), 0o600); err != nil {
		t.Fatal(err)
	}
	// a hard link sees the same blocks: after Wipe they hold zeros
	keep := filepath.Join(dir, "link")
	if err := os.Link(f, keep); err != nil {
		t.Fatal(err)
	}
	if err := Wipe(f); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(f); !os.IsNotExist(err) {
		t.Errorf("still there: %v", err)
	}
	b, _ := os.ReadFile(keep)
	for _, c := range b {
		if c != 0 {
			t.Fatalf("content not overwritten: %q", b)
		}
	}
	if len(b) != len("secret key material") {
		t.Errorf("size changed: %d", len(b))
	}
	if err := Wipe(f); err != nil {
		t.Errorf("missing file: %v", err)
	}
}

func TestWipeGlob(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"a", "b"} {
		os.MkdirAll(filepath.Join(dir, n), 0o700)
		os.WriteFile(filepath.Join(dir, n, "tunnel.ovpn"), []byte("k"), 0o600)
	}
	os.WriteFile(filepath.Join(dir, "a", "other"), []byte("k"), 0o600)
	if n := WipeGlob(filepath.Join(dir, "*", "tunnel.ovpn")); n != 2 {
		t.Errorf("wiped %d", n)
	}
	if _, err := os.Stat(filepath.Join(dir, "a", "other")); err != nil {
		t.Errorf("other file touched: %v", err)
	}
}
