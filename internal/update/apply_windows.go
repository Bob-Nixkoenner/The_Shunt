package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/sys/windows"
)

// Apply downloads the setup of release tag, checks it against the signed
// checksum list and starts it with the Windows admin prompt (UAC). The setup
// stops the tray and the service, replaces the files and starts them again.
//
// Report M-08: the setup lies in the user's temp folder; between the check
// and the start another program of the same user could swap it. So the file
// is opened again without write or delete sharing, hashed once more through
// that handle, and the handle stays open until the setup has been started:
// nobody can change, rename or delete it in between (running it only needs
// read sharing).
func Apply(ctx context.Context, tag string) error {
	path, want, err := download(ctx, tag, "the-shunt-windows-amd64-setup.exe")
	if err != nil {
		return err
	}
	h, err := lockFile(path)
	if err != nil {
		return fmt.Errorf("could not lock the setup: %w", err)
	}
	defer windows.CloseHandle(h)
	sum := sha256.New()
	if _, err := io.Copy(sum, handleReader{h}); err != nil {
		return fmt.Errorf("could not check the setup: %w", err)
	}
	if got := hex.EncodeToString(sum.Sum(nil)); got != want {
		return fmt.Errorf("the setup changed after the check (%s, want %s) - nothing was started", got, want)
	}
	verb, file := windows.StringToUTF16Ptr("runas"), windows.StringToUTF16Ptr(path)
	if err := windows.ShellExecute(0, verb, file, nil, nil, windows.SW_SHOWNORMAL); err != nil {
		return fmt.Errorf("could not start the setup: %w", err)
	}
	return nil
}

// lockFile opens path for reading and lets others only read it (no write,
// no delete or rename) while the handle is open.
func lockFile(path string) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	return windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil,
		windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
}

// handleReader reads from a handle that stays owned by the caller.
type handleReader struct{ h windows.Handle }

func (r handleReader) Read(p []byte) (int, error) {
	var n uint32
	if err := windows.ReadFile(r.h, p, &n, nil); err != nil {
		return int(n), err
	}
	if n == 0 && len(p) > 0 {
		return 0, io.EOF
	}
	return int(n), nil
}

func canApply() bool { return true }
