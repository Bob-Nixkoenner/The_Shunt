package defense

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"
)

// DefaultSSHBanner is the version string the SSH decoy announces.
const DefaultSSHBanner = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5"

const (
	sshMaxAuth      = 6
	sshMaxConc      = 16
	sshStepTimeout  = 10 * time.Second
	sshDefaultDelay = time.Second
)

// LoadOrCreateHostKey reads an ed25519 host key from path (PEM, PKCS#8). If it
// does not exist a new one is created with mode 0600 (never through a
// symbolic link). A key file that is a link or no regular file is refused;
// one that cannot be parsed is moved aside (".bad") and replaced, so a
// damaged file does not switch the ssh decoy off for good. Looser rights on
// an existing key are cut back to 0600. An empty path keeps the key in
// memory only.
func LoadOrCreateHostKey(path string) (ssh.Signer, error) {
	if path != "" {
		if fi, err := os.Lstat(path); err == nil {
			if !fi.Mode().IsRegular() {
				return nil, fmt.Errorf("ssh decoy host key %s: not a regular file", path)
			}
			if fi.Mode().Perm()&0o077 != 0 {
				_ = os.Chmod(path, 0o600)
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return nil, err
			}
			if s, err := ssh.ParsePrivateKey(b); err == nil {
				return s, nil
			}
			if err := os.Rename(path, path+".bad"); err != nil {
				return nil, fmt.Errorf("ssh decoy host key %s: unreadable and cannot be moved aside: %w", path, err)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if path != "" {
		der, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
		pemb := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		// O_EXCL: fails on any existing name, a (dangling) symlink included
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return nil, err
		}
		if _, err := f.Write(pemb); err != nil {
			f.Close()
			os.Remove(path)
			return nil, err
		}
		if err := f.Close(); err != nil {
			return nil, err
		}
	}
	return ssh.NewSignerFromKey(priv)
}

// sshConfig builds the server side: every login fails, no channel is ever
// accepted. Each password or keyboard-interactive try is reported with only
// the user name and the password digest.
func (d *Decoys) sshConfig(ctx context.Context, src netip.Addr, port int, signer ssh.Signer, conn net.Conn) *ssh.ServerConfig {
	banner := d.SSHBanner
	if banner == "" {
		banner = DefaultSSHBanner
	}
	report := func(md ssh.ConnMetadata, pw string) error {
		d.login(src, port, "ssh", md.User(), pw, " client="+cleanField(string(md.ClientVersion()))+toolDetail(ToolFromSSHClient(string(md.ClientVersion()))))
		_ = conn.SetDeadline(time.Now().Add(sshStepTimeout))
		if d.SSHDelay > 0 {
			t := time.NewTimer(d.SSHDelay)
			select {
			case <-t.C:
			case <-ctx.Done():
				t.Stop()
			}
		}
		return errors.New("denied")
	}
	cfg := &ssh.ServerConfig{
		MaxAuthTries:  sshMaxAuth,
		ServerVersion: banner,
		PasswordCallback: func(md ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			return nil, report(md, string(pw))
		},
		KeyboardInteractiveCallback: func(md ssh.ConnMetadata, ch ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			ans, err := ch("", "", []string{"Password: "}, []bool{false})
			pw := ""
			if err == nil && len(ans) > 0 {
				pw = ans[0]
			}
			return nil, report(md, pw)
		},
	}
	cfg.AddHostKey(signer)
	return cfg
}

func (d *Decoys) hostKey() (ssh.Signer, error) {
	d.keyMu.Lock()
	defer d.keyMu.Unlock()
	if d.signer == nil {
		s, err := LoadOrCreateHostKey(d.HostKeyPath)
		if err != nil {
			return nil, err
		}
		d.signer = s
	}
	return d.signer, nil
}

// sshTrap speaks real SSH up to authentication and refuses everything.
func (d *Decoys) sshTrap(ctx context.Context, c net.Conn, src netip.Addr, port int) {
	select {
	case d.sshSem <- struct{}{}:
		defer func() { <-d.sshSem }()
	default:
		return // 16 at once is enough
	}
	signer, err := d.hostKey()
	if err != nil {
		return
	}
	_ = c.SetDeadline(time.Now().Add(sshStepTimeout))
	sc, chans, reqs, err := ssh.NewServerConn(c, d.sshConfig(ctx, src, port, signer, c))
	if err != nil {
		return
	}
	// cannot happen (all logins fail); never serve anything anyway
	go Guard(d.Log, "ssh decoy requests", func() { ssh.DiscardRequests(reqs) })
	go Guard(d.Log, "ssh decoy channels", func() {
		for nc := range chans {
			_ = nc.Reject(ssh.Prohibited, "no")
		}
	})
	sc.Close()
}
