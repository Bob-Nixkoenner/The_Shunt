package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ErrNotSupported: this platform updates by hand (see Info.Command).
var ErrNotSupported = errors.New("installing updates from the app is not supported here - use the command")

// releaseURL is the download address of a release asset.
func releaseURL(tag, name string) string {
	return "https://github.com/" + Repo + "/releases/download/" + tag + "/" + name
}

func get(ctx context.Context, url string, limit int64, to io.Writer) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	resp, err := (&http.Client{Timeout: 10 * time.Minute}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: %s", filepath.Base(url), resp.Status)
	}
	n, err := io.Copy(to, io.LimitReader(resp.Body, limit+1))
	if err == nil && n > limit {
		err = fmt.Errorf("download %s is larger than expected", filepath.Base(url))
	}
	return err
}

type buf struct{ b []byte }

func (b *buf) Write(p []byte) (int, error) { b.b = append(b.b, p...); return len(p), nil }

// Download fetches the release asset name into a new private directory and
// returns its path, but only if the release's SHA256SUMS carries the release
// key's signature and lists the exact hash of the downloaded file.
func Download(ctx context.Context, tag, name string) (string, error) {
	if !verRe.MatchString(tag) {
		return "", fmt.Errorf("%q is not a release tag", tag)
	}
	var sums, sig buf
	if err := get(ctx, releaseURL(tag, "SHA256SUMS"), 1<<20, &sums); err != nil {
		return "", err
	}
	if err := get(ctx, releaseURL(tag, "SHA256SUMS.sig"), 1<<16, &sig); err != nil {
		return "", err
	}
	if err := VerifySums(sums.b, sig.b); err != nil {
		return "", fmt.Errorf("release %s: %w - nothing was installed", tag, err)
	}
	want, ok := SumFor(sums.b, name)
	if !ok {
		return "", fmt.Errorf("the signed list of %s has no %s", tag, name)
	}
	dir, err := os.MkdirTemp("", "shunt-update-")
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o700)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	err = get(ctx, releaseURL(tag, name), 300<<20, io.MultiWriter(f, h))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && !strings.EqualFold(hex.EncodeToString(h.Sum(nil)), want) {
		err = fmt.Errorf("%s does not match the signed checksum - not installed", name)
	}
	if err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	return path, nil
}
