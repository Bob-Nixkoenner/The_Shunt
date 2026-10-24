package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"github.com/jchv/go-webview2"
	"golang.org/x/sys/windows"
)

// The window is an own window with the WebView2 runtime inside (part of
// Windows 11 and of current Edge): no tabs, no address bar, its own taskbar
// entry. Without that runtime it falls back to Microsoft Edge/Chrome in app
// mode, and without a browser to the default browser. Closing the window
// only ends it; the tray keeps running.

var onHidden = func() {}

var win struct {
	mu     sync.Mutex
	prefix string
	icon   []byte
	cmd    *exec.Cmd // fallback: browser in app mode
	wv     webview2.WebView
	open   bool // the WebView2 window exists
}

func windowInit(title, allowedPrefix string, icon []byte) {
	win.mu.Lock()
	win.prefix = allowedPrefix
	win.icon = icon
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
	if win.open {
		focusWindow(win.wv)
		return
	}
	if win.cmd != nil && win.cmd.ProcessState == nil {
		return // already open; Edge keeps its page
	}
	if uri == "" {
		uri = win.prefix
	}
	if showWebView(uri) {
		return
	}
	exe := browser()
	if exe == "" {
		_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", uri).Start()
		return
	}
	profile := filepath.Join(localAppData(), "Shunt", "window")
	cmd := exec.Command(exe, "--app="+uri, "--user-data-dir="+profile, "--window-size=1240,860",
		"--no-first-run", "--no-default-browser-check", "--disable-extensions",
		"--disable-features=Translate,TranslateUI,msEdgeTranslate,msEdgeFollow")
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

// localAppData is %LOCALAPPDATA%, also when the variable is missing (started
// by a scheduled task): WebView2 fails with a relative data folder.
func localAppData() string {
	if d := os.Getenv("LOCALAPPDATA"); d != "" {
		return d
	}
	d, _ := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, 0)
	return d
}

// showWebView opens the WebView2 window; false if the runtime is missing.
// The window lives on its own OS thread (its message loop).
func showWebView(uri string) bool {
	type result struct{ wv webview2.WebView }
	ready := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		wv := webview2.NewWithOptions(webview2.WebViewOptions{
			AutoFocus: true,
			DataPath:  filepath.Join(localAppData(), "Shunt", "webview"),
			WindowOptions: webview2.WindowOptions{
				Title: "The Shunt", Width: 1240, Height: 860, Center: true,
			},
		})
		if wv == nil {
			ready <- result{}
			return
		}
		setWindowIcon(wv, win.icon)
		wv.Navigate(uri)
		ready <- result{wv}
		wv.Run()
		win.mu.Lock()
		win.open = false
		win.wv = nil
		win.mu.Unlock()
		wv.Destroy()
		onHidden()
	}()
	// the caller holds win.mu; the goroutine only takes it after Run
	r := <-ready
	if r.wv == nil {
		return false
	}
	win.wv, win.open = r.wv, true
	return true
}

var (
	user32                  = windows.NewLazySystemDLL("user32.dll")
	procSendMessage         = user32.NewProc("SendMessageW")
	procCreateIconFromRes   = user32.NewProc("CreateIconFromResourceEx")
	procSetForegroundWindow = user32.NewProc("SetForegroundWindow")
	procShowWindow          = user32.NewProc("ShowWindow")
)

// setWindowIcon gives the window (title bar, taskbar) the tray's PNG icon.
func setWindowIcon(wv webview2.WebView, png []byte) {
	if len(png) == 0 {
		return
	}
	const wmSetIcon, iconSmall, iconBig = 0x80, 0, 1
	for i, size := range []uintptr{16, 32} {
		h, _, _ := procCreateIconFromRes.Call(uintptr(unsafe.Pointer(&png[0])), uintptr(len(png)), 1, 0x00030000, size, size, 0)
		if h != 0 {
			kind := uintptr(iconSmall)
			if i == 1 {
				kind = iconBig
			}
			procSendMessage.Call(uintptr(wv.Window()), wmSetIcon, kind, h)
		}
	}
}

// focusWindow brings an open window to the front.
func focusWindow(wv webview2.WebView) {
	if wv == nil {
		return
	}
	h := uintptr(wv.Window())
	procShowWindow.Call(h, 9) // SW_RESTORE
	procSetForegroundWindow.Call(h)
}

func windowQuit() {
	win.mu.Lock()
	defer win.mu.Unlock()
	if win.wv != nil {
		win.wv.Destroy()
	}
	if win.cmd != nil && win.cmd.Process != nil && win.cmd.ProcessState == nil {
		_ = win.cmd.Process.Kill()
	}
}

func windowVisible() bool {
	win.mu.Lock()
	defer win.mu.Unlock()
	return win.open || win.cmd != nil && win.cmd.ProcessState == nil
}

// windowMain blocks and runs the message loop of the tray icon. The tray
// library creates its hidden window on the main thread (it locks it in init)
// and leaves pumping that thread's messages to us; without the pump clicks on
// the icon never arrive. Quit ends the process.
func windowMain() {
	getMessage := user32.NewProc("GetMessageW")
	translate := user32.NewProc("TranslateMessage")
	dispatch := user32.NewProc("DispatchMessageW")
	var msg [48]byte // MSG, big enough for 64-bit
	for {
		r, _, _ := getMessage.Call(uintptr(unsafe.Pointer(&msg[0])), 0, 0, 0)
		if int32(r) <= 0 {
			return
		}
		translate.Call(uintptr(unsafe.Pointer(&msg[0])))
		dispatch.Call(uintptr(unsafe.Pointer(&msg[0])))
	}
}
