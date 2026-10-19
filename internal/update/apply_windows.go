package update

import (
	"context"
	"fmt"

	"golang.org/x/sys/windows"
)

// Apply downloads the setup of release tag, checks it against the signed
// checksum list and starts it with the Windows admin prompt (UAC). The setup
// stops the tray and the service, replaces the files and starts them again.
func Apply(ctx context.Context, tag string) error {
	path, err := Download(ctx, tag, "the-shunt-windows-amd64-setup.exe")
	if err != nil {
		return err
	}
	verb, file := windows.StringToUTF16Ptr("runas"), windows.StringToUTF16Ptr(path)
	if err := windows.ShellExecute(0, verb, file, nil, nil, windows.SW_SHOWNORMAL); err != nil {
		return fmt.Errorf("could not start the setup: %w", err)
	}
	return nil
}

func canApply() bool { return true }
