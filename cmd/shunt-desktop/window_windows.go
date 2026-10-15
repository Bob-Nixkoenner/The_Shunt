package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
)

// The window is Microsoft Edge in app mode (installed on every Windows 11):
// a plain window without tabs or address bar that shows the local web UI.
// Closing it only ends that process; the tray keeps running.

var onHidden = func() {}

var win struct {
	mu     sync.Mutex
	prefix string
	cmd    *exec.Cmd
}

func windowInit(title, allowedPrefix string, icon []byte) {
	win.mu.Lock()
	win.prefix = allowedPrefix
	win.mu.Unlock()
}

func browser() string {
	for _, env := range []string{"ProgramFiles(x86)", "ProgramFiles", "LocalAppData"} {
		for _, rel := range []string{`Microsoft\Edge\Application\msedge.exe`, `Google\Chrome\Application\chrome.exe`} {
			p := filepath.Join(os.Getenv(env), rel)
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	return ""
}

// windowShow shows the window (thread safe); uri "" keeps the current page.
func windowShow(uri string) {
	win.mu.Lock()
	defer win.mu.Unlock()
	if win.cmd != nil && win.cmd.ProcessState == nil {
		return // already open; Edge keeps its page
	}
	if uri == "" {
		uri = win.prefix
	}
	exe := browser()
	if exe == "" {
		_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", uri).Start()
		return
	}
	profile := filepath.Join(os.Getenv("LOCALAPPDATA"), "Shunt", "window")
	cmd := exec.Command(exe, "--app="+uri, "--user-data-dir="+profile, "--window-size=1240,860",
		"--no-first-run", "--no-default-browser-check", "--disable-extensions")
	cmd.SysProcAttr = &syscall.SysProcAttr{}
	if err := cmd.Start(); err != nil {
		return
	}
	win.cmd = cmd
	go func() {
		_ = cmd.Wait()
		onHidden()
	}()
}

func windowQuit() {
	win.mu.Lock()
	defer win.mu.Unlock()
	if win.cmd != nil && win.cmd.Process != nil && win.cmd.ProcessState == nil {
		_ = win.cmd.Process.Kill()
	}
}

func windowVisible() bool {
	win.mu.Lock()
	defer win.mu.Unlock()
	return win.cmd != nil && win.cmd.ProcessState == nil
}

// windowMain blocks: the tray runs its own message loop on Windows, and
// Quit ends the process.
func windowMain() { select {} }
