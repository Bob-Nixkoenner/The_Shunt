package ui

import (
	"errors"
	"net/url"
	"os/exec"
	"runtime"
)

// openURL opens an https link in the user's default browser. The desktop
// window (WebView2) shows no external pages itself, so links in the UI ask
// the app to do it. Only https URLs; no shell is involved.
func openURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return errors.New("only https links can be opened")
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", u.String())
	case "darwin":
		cmd = exec.Command("open", u.String())
	default:
		cmd = exec.Command("xdg-open", u.String())
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}
