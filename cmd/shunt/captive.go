package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/Bob-Nixkoenner/the_shunt/internal/api"
	"github.com/Bob-Nixkoenner/the_shunt/internal/engine"
)

// captivePortalURL is plain HTTP on purpose: the portal has to be able to
// intercept it.
const captivePortalURL = "http://neverssl.com/"

// browsers in order of preference; firefox-like ones take a profile dir,
// chromium-like ones a user data dir. Either way a *new* browser process
// starts: handing the URL to a running browser would open it in that
// browser's route.
var captiveBrowsers = []struct {
	bin      string
	chromium bool
}{
	{"firefox", false}, {"firefox-esr", false}, {"librewolf", false},
	{"chromium", true}, {"chromium-browser", true}, {"brave-browser", true}, {"brave", true}, {"google-chrome", true},
}

// captive opens a throwaway browser that bypasses the tunnels, for Wi-Fi
// login pages (hotel, train, airport). Nothing it stores survives.
func captive(c *api.Client, args []string) error {
	fs := flag.NewFlagSet("captive", flag.ExitOnError)
	browser := fs.String("browser", "", "browser binary (default: first of firefox, chromium, brave, chrome)")
	url := fs.String("url", "", "page to open (default: the login page shuntd found, else "+captivePortalURL+")")
	_ = fs.Parse(args)
	if *url == "" {
		*url = captivePortalURL
		var st api.Status
		if c.Do("GET", "/v1/status", nil, &st) == nil && st.CaptiveURL != "" {
			*url = st.CaptiveURL
		}
	}

	bin, chromium := "", false
	for _, b := range captiveBrowsers {
		if *browser != "" && b.bin != *browser {
			continue
		}
		if p, err := exec.LookPath(b.bin); err == nil {
			bin, chromium = p, b.chromium
			break
		}
	}
	if bin == "" && *browser != "" {
		p, err := exec.LookPath(*browser)
		if err != nil {
			return err
		}
		bin = p
	}
	if bin == "" {
		return fmt.Errorf("no supported browser found (firefox, chromium, brave, chrome); use --browser")
	}
	dir, err := os.MkdirTemp(os.Getenv("XDG_RUNTIME_DIR"), "shunt-captive-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	// this process (and so the browser) goes direct
	if err := c.Do("POST", "/v1/run", api.RunRequest{Group: engine.ViaGroupName("direct")}, nil); err != nil {
		return err
	}
	var cmd *exec.Cmd
	if chromium {
		cmd = exec.Command(bin, "--user-data-dir="+dir, "--no-first-run", "--no-default-browser-check", *url)
	} else {
		cmd = exec.Command(bin, "--no-remote", "--profile", dir, *url)
	}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	fmt.Fprintf(os.Stderr, "login browser (%s, direct, throwaway profile in %s); close it when you are online\n", filepath.Base(bin), dir)
	return cmd.Run()
}
