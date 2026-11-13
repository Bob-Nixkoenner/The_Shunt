// Package secfile removes files that held secrets (a tunnel's keys, bridge
// lines) for the few seconds a helper program needs to read them.
//
// Wipe overwrites the content with zeros, flushes it and then removes the
// file. On flash storage (f2fs/ext4 on a phone) the old blocks may still be
// kept by the controller; overwriting is best effort, the real protection is
// that the file exists only briefly, in an app-private folder, under the
// device's file-based encryption.
package secfile

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// Wipe overwrites path with zeros, syncs it and removes it. A missing file
// is not an error.
func Wipe(path string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if fi.Mode().IsRegular() && fi.Size() > 0 {
		if f, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil {
			zero := make([]byte, 32<<10)
			for left := fi.Size(); left > 0; {
				n := int64(len(zero))
				if left < n {
					n = left
				}
				if _, err := f.Write(zero[:n]); err != nil {
					break
				}
				left -= n
			}
			_ = f.Sync()
			_ = f.Close()
		}
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// WipeGlob wipes every file matching pattern (filepath.Match syntax) and
// returns how many were removed.
func WipeGlob(pattern string) int {
	m, _ := filepath.Glob(pattern)
	n := 0
	for _, f := range m {
		if Wipe(f) == nil {
			n++
		}
	}
	return n
}
