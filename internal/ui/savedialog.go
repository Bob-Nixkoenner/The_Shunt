package ui

import (
	"context"
	"errors"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// errNoDialog says there is no native save dialog on this system: the caller
// falls back to the download folder.
var errNoDialog = errors.New("no save dialog available")

// errCancelled is returned when the user closed the dialog.
var errCancelled = errors.New("cancelled")

// saveDialogFn asks the user where to save def (a full path suggestion). It
// is a variable so tests do not open a window.
var saveDialogFn = saveDialog

func saveDialog(def string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	var c *exec.Cmd
	switch {
	case runtime.GOOS == "windows":
		// the path travels as an argument, never inside the script text
		c = exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command",
			`Add-Type -AssemblyName System.Windows.Forms; $d=New-Object System.Windows.Forms.SaveFileDialog; $d.FileName=$args[0]; if($d.ShowDialog() -eq 'OK'){$d.FileName}`, def)
	case runtime.GOOS == "darwin":
		c = exec.CommandContext(ctx, "osascript", "-e", `on run argv
POSIX path of (choose file name default name (item 1 of argv))
end run`, def[strings.LastIndexAny(def, `/\`)+1:])
	default:
		if p, err := exec.LookPath("zenity"); err == nil {
			c = exec.CommandContext(ctx, p, "--file-selection", "--save", "--confirm-overwrite", "--filename="+def)
		} else if p, err := exec.LookPath("kdialog"); err == nil {
			c = exec.CommandContext(ctx, p, "--getsavefilename", def)
		} else {
			return "", errNoDialog
		}
	}
	out, err := c.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) { // closed or Cancel
			return "", errCancelled
		}
		return "", errNoDialog
	}
	p := strings.TrimSpace(string(out))
	if p == "" {
		return "", errCancelled
	}
	return p, nil
}
