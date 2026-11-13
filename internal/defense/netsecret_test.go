package defense

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// The decoy identity follows the network: two networks give unrelated lock
// credentials and host keys, the same network the same ones after a restart
// (a new Decoys with the same secret file); nothing is stored per network.
func TestDecoyIdentityPerNetwork(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "decoy-secret")
	ident := func(d *Decoys, net string) (BaitCreds, []byte) {
		d.SetNetKey(net)
		b, ok := d.bait()
		if !ok || !b.valid() {
			t.Fatalf("no bait for %q", net)
		}
		s, err := d.hostKey()
		if err != nil {
			t.Fatal(err)
		}
		return b, s.PublicKey().Marshal()
	}
	d1 := NewDecoys(nil, nil)
	d1.SecretPath = secret
	bA, kA := ident(d1, "aaaa1111")
	bB, kB := ident(d1, "bbbb2222")
	if bA == bB || bA.User == bB.User && bA.Password == bB.Password || bytes.Equal(kA, kB) {
		t.Fatalf("two networks share an identity: %+v %+v", bA, bB)
	}
	if bA.Password == bB.Password || bA.Token == bB.Token {
		t.Fatal("password or token repeats across networks")
	}
	// back in network A: the same as before
	if b, k := ident(d1, "aaaa1111"); b != bA || !bytes.Equal(k, kA) {
		t.Fatal("same network, other identity")
	}
	// restart: a new decoy set with the same secret file
	d2 := NewDecoys(nil, nil)
	d2.SecretPath = secret
	if b, k := ident(d2, "aaaa1111"); b != bA || !bytes.Equal(k, kA) {
		t.Fatal("identity changed after a restart")
	}
	// only the secret is on disk, 0600, no per-network files
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Fatalf("files: %v", ents)
	}
	if fi, _ := os.Stat(secret); fi.Mode().Perm() != 0o600 || fi.Size() != secretLen {
		t.Fatalf("secret file %v %d", fi.Mode(), fi.Size())
	}
	// another installation (other secret): other identity in the same network
	d3 := NewDecoys(nil, nil)
	d3.SecretPath = filepath.Join(t.TempDir(), "decoy-secret")
	if b, _ := ident(d3, "aaaa1111"); b == bA {
		t.Fatal("two installations share an identity")
	}
}

// The manager switches the identity with the network.
func TestManagerSwitchesDecoyIdentity(t *testing.T) {
	m, _ := newTestManager(t, nil, nil)
	m.dec.SecretPath = filepath.Join(t.TempDir(), "decoy-secret")
	m.SetNetwork("net-one", ClassUnknown)
	a, _ := m.dec.bait()
	m.SetNetwork("net-two", ClassUnknown)
	b, _ := m.dec.bait()
	if a == b {
		t.Fatal("network change kept the lock credentials")
	}
}

// A damaged secret is moved aside and replaced; a link is refused.
func TestDecoySecretFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "decoy-secret")
	if err := os.WriteFile(p, []byte("short"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := LoadOrCreateSecret(p)
	if err != nil || len(s) != secretLen {
		t.Fatalf("%v %d", err, len(s))
	}
	if _, err := os.Stat(p + ".bad"); err != nil {
		t.Fatal("damaged file not moved aside")
	}
	l := filepath.Join(dir, "link")
	_ = os.Symlink(p, l)
	if _, err := LoadOrCreateSecret(l); err == nil {
		t.Fatal("a link must be refused")
	}
}
