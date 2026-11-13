package defense

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
)

// BaitCreds are the lock credentials ("fake wins") the HTTP decoy hands out
// in its bait files (/.env, /.git/config, /config.php.bak). They are random
// per installation, live only in a local file (mode 0600) and open nothing:
// no real service knows them. Whoever presents the password or the token at a
// login decoy (SSH, telnet, HTTP) has read a bait file and is using what it
// found, which is proof of hostile intent.
type BaitCreds struct {
	User     string `json:"user"`
	Password string `json:"password"`
	Token    string `json:"token"`
}

// baitUsers are plausible service account names; one is picked per install.
var baitUsers = []string{"deploy", "backup", "svc_web", "appuser", "dbadmin", "ci_runner", "webadmin", "jenkins"}

const baitAlphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

func randomIndex(n int) (int, error) {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0, err
	}
	return int(v.Int64()), nil
}

// NewBaitCreds makes a fresh random set: a user name with a number, a
// 20-character password and a 32-hex-digit token.
func NewBaitCreds() (BaitCreds, error) {
	i, err := randomIndex(len(baitUsers))
	if err != nil {
		return BaitCreds{}, err
	}
	n, err := randomIndex(90)
	if err != nil {
		return BaitCreds{}, err
	}
	pw := make([]byte, 20)
	for k := range pw {
		j, err := randomIndex(len(baitAlphabet))
		if err != nil {
			return BaitCreds{}, err
		}
		pw[k] = baitAlphabet[j]
	}
	tok := make([]byte, 16)
	if _, err := rand.Read(tok); err != nil {
		return BaitCreds{}, err
	}
	return BaitCreds{User: fmt.Sprintf("%s%02d", baitUsers[i], n+10), Password: string(pw), Token: "ak_" + hex.EncodeToString(tok)}, nil
}

func (b BaitCreds) valid() bool { return len(b.Password) >= 12 && len(b.Token) >= 12 && b.User != "" }

// Match reports whether a presented secret is the bait password or token.
// The user name does not matter: a thief may try the password with root.
// Constant time, so the check leaks nothing about the bait.
func (b BaitCreds) Match(secret string) bool {
	if !b.valid() || secret == "" {
		return false
	}
	p := subtle.ConstantTimeCompare([]byte(secret), []byte(b.Password))
	t := subtle.ConstantTimeCompare([]byte(secret), []byte(b.Token))
	return p|t == 1
}

// LoadOrCreateBait reads the lock credentials from path (JSON) or creates
// them with mode 0600 (never through a symbolic link). A file that is a link
// or no regular file is refused; one that cannot be parsed is moved aside
// (".bad") and replaced. An empty path keeps them in memory only (new ones on
// every start).
func LoadOrCreateBait(path string) (BaitCreds, error) {
	if path != "" {
		if fi, err := os.Lstat(path); err == nil {
			if !fi.Mode().IsRegular() {
				return BaitCreds{}, fmt.Errorf("bait file %s: not a regular file", path)
			}
			if fi.Mode().Perm()&0o077 != 0 {
				_ = os.Chmod(path, 0o600)
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return BaitCreds{}, err
			}
			var b BaitCreds
			if json.Unmarshal(raw, &b) == nil && b.valid() {
				return b, nil
			}
			if err := os.Rename(path, path+".bad"); err != nil {
				return BaitCreds{}, fmt.Errorf("bait file %s: unreadable and cannot be moved aside: %w", path, err)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return BaitCreds{}, err
		}
	}
	b, err := NewBaitCreds()
	if err != nil {
		return BaitCreds{}, err
	}
	if path == "" {
		return b, nil
	}
	raw, _ := json.Marshal(b)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return BaitCreds{}, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return BaitCreds{}, err
	}
	if _, err := f.Write(raw); err != nil {
		f.Close()
		os.Remove(path)
		return BaitCreds{}, err
	}
	return b, f.Close()
}

// bait returns the lock credentials, loading them on first use. ok is false
// when they cannot be had (the bait files then answer 404 and nothing
// matches).
func (d *Decoys) bait() (BaitCreds, bool) {
	d.keyMu.Lock()
	defer d.keyMu.Unlock()
	if d.baitCreds == nil {
		b, err := LoadOrCreateBait(d.BaitPath)
		if err != nil {
			if d.Log != nil {
				d.Log.Debug("defense: bait credentials", "err", err)
			}
			return BaitCreds{}, false
		}
		d.baitCreds = &b
	}
	return *d.baitCreds, true
}

// login reports one login try on a login decoy (via = ssh, telnet, http). A
// try with the bait password or token becomes a KindBait event (high); every
// other one a KindCowrie event with only the user name and the password
// digest. extra is appended to the detail (" tool=...").
func (d *Decoys) login(src netip.Addr, port int, via, user, pw, extra string) {
	if b, ok := d.bait(); ok && b.Match(pw) {
		d.hit(Hit{Src: src, Port: port, Kind: KindBait, Sev: SevHigh,
			Detail: "bait used via=" + via + " user=" + cleanField(user) + extra})
		return
	}
	d.hit(Hit{Src: src, Port: port, Kind: KindCowrie, Sev: SevMedium,
		Detail: via + " login user=" + cleanField(user) + " " + PasswordDigest(pw) + extra})
}
