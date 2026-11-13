package defense

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

// Per-network decoy identity. The lock credentials (bait.go) and the ssh
// decoy's host key are derived from one random secret of this installation
// and the key of the network the machine is in (Manager.SetNetwork, a hash of
// interface, SSID and gateway; never stored or logged in clear). The same
// network gives the same credentials and host key after every restart; two
// networks give unrelated ones, so whoever fetches /.env or the host key in
// two places cannot tell it is the same device. Nothing is stored per
// network: forgetting a network leaves nothing behind.

const secretLen = 32

// LoadOrCreateSecret reads the installation secret from path or creates it
// (mode 0600, never through a symbolic link). A file that is a link or no
// regular file is refused; one of the wrong size is moved aside (".bad") and
// replaced. An empty path keeps it in memory only (new on every start).
func LoadOrCreateSecret(path string) ([]byte, error) {
	if path != "" {
		if fi, err := os.Lstat(path); err == nil {
			if !fi.Mode().IsRegular() {
				return nil, fmt.Errorf("decoy secret %s: not a regular file", path)
			}
			if fi.Mode().Perm()&0o077 != 0 {
				_ = os.Chmod(path, 0o600)
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return nil, err
			}
			if len(raw) == secretLen {
				return raw, nil
			}
			if err := os.Rename(path, path+".bad"); err != nil {
				return nil, fmt.Errorf("decoy secret %s: unreadable and cannot be moved aside: %w", path, err)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	s := make([]byte, secretLen)
	if _, err := rand.Read(s); err != nil {
		return nil, err
	}
	if path == "" {
		return s, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if _, err := f.Write(s); err != nil {
		f.Close()
		os.Remove(path)
		return nil, err
	}
	return s, f.Close()
}

// netStream is a deterministic byte stream for one purpose in one network.
func netStream(secret []byte, purpose, netKey string) io.Reader {
	// HKDF-SHA256: extract with the purpose as salt, expand with the network
	// key; up to 255*32 bytes, far more than a credential set needs
	prk, _ := hkdf.Extract(sha256.New, secret, []byte("the-shunt decoy "+purpose))
	out, _ := hkdf.Expand(sha256.New, prk, "net="+netKey, 255*32)
	return &byteReader{b: out}
}

type byteReader struct{ b []byte }

func (r *byteReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}

// netBait derives the lock credentials of one network.
func netBait(secret []byte, netKey string) (BaitCreds, error) {
	return newBaitCreds(netStream(secret, "bait", netKey))
}

// netHostKey derives the ssh decoy host key of one network.
func netHostKey(secret []byte, netKey string) (ssh.Signer, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(netStream(secret, "ssh-host-ed25519", netKey), seed); err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(seed))
}
