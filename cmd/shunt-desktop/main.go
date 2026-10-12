// Command shunt-desktop is The Shunt's desktop app: a tray icon that always
// shows whether the tunnels protect you, desktop notifications when that
// changes, and the web UI in its own window. It runs as the desktop user
// and talks to shuntd through the same API as the CLI.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
	"time"

	"fyne.io/systray"

	"github.com/Bob-Nixkoenner/the_shunt/internal/api"
	"github.com/Bob-Nixkoenner/the_shunt/internal/desktopapp"
	"github.com/Bob-Nixkoenner/the_shunt/internal/ui"
)

var version = "dev"

func init() { runtime.LockOSThread() } // GTK must own the main thread

const maxTunnelItems = 8

func main() {
	sock := flag.String("s", "/run/shunt/shuntd.sock", "shuntd socket")
	hidden := flag.Bool("hidden", false, "start in the tray without opening the window")
	showVersion := flag.Bool("version", false, "print the version")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}

	single, err := desktopapp.Claim()
	if err != nil {
		log.Fatal(err)
	}
	if single == nil {
		return // the running instance shows its window
	}

	self, _ := os.Executable()
	shunt := "shunt" // CLI next to us, used by leak test and app launches
	if p := sibling(self, "shunt"); p != "" {
		shunt = p
	}
	client := api.NewClient(*sock)
	srv := &ui.Server{Socket: *sock, Self: shunt, Client: client}
	ln, url, err := srv.Listen(0)
	if err != nil {
		log.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()

	windowInit("The Shunt", "http://"+ln.Addr().String()+"/", desktopapp.Icon(desktopapp.OK))
	var loadOnce sync.Once
	show := func() {
		first := false
		loadOnce.Do(func() { first = true })
		if first {
			windowShow(url) // carries the one-time token; the UI then uses its cookie
		} else {
			windowShow("")
		}
	}
	go single.Requests(show)

	app := &trayApp{client: client, notifier: desktopapp.NewNotifier(), show: show, exe: self, shunt: shunt, sock: *sock}
	start, end := systray.RunWithExternalLoop(app.onReady, func() {})
	start()
	defer end()

	if !*hidden {
		show()
	}
	windowMain()
}

func sibling(self, name string) string {
	p := self[:len(self)-len("shunt-desktop")] + name
	if fi, err := os.Stat(p); err == nil && !fi.IsDir() && len(self) > len("shunt-desktop") {
		return p
	}
	return ""
}

type trayApp struct {
	client   *api.Client
	notifier *desktopapp.Notifier
	show     func()
	exe      string
	shunt    string // CLI, for the captive portal browser
	sock     string

	title     *systray.MenuItem
	panic     *systray.MenuItem
	autostart *systray.MenuItem
	tunnels   []*systray.MenuItem
}

func (a *trayApp) onReady() {
	systray.SetIcon(desktopapp.Icon(desktopapp.Bad))
	systray.SetTitle("The Shunt")
	systray.SetTooltip("The Shunt")
	a.title = systray.AddMenuItem("…", "")
	a.title.Disable()
	for i := 0; i < maxTunnelItems; i++ {
		it := systray.AddMenuItem("", "")
		it.Disable()
		it.Hide()
		a.tunnels = append(a.tunnels, it)
	}
	systray.AddSeparator()
	open := systray.AddMenuItem("Open The Shunt", "Show the window")
	a.panic = systray.AddMenuItem("PANIC – block all traffic", "Drop everything except loopback, now")
	captive := systray.AddMenuItem("Wi-Fi login page…", "Hotel/train Wi-Fi: open a throwaway browser that goes past the tunnels")
	systray.AddSeparator()
	restart := systray.AddMenuItem("Restart service", "Restart shuntd (asks for the admin password); tunnelled apps are blocked for a moment")
	restartAll := systray.AddMenuItem("Restart service and app", "Restart shuntd, then this tray app and window")
	systray.AddSeparator()
	a.autostart = systray.AddMenuItemCheckbox("Start at login", "Show the tray icon after login", desktopapp.AutostartEnabled())
	quit := systray.AddMenuItem("Quit tray", "Close the tray icon and window (protection keeps running)")
	systray.SetOnTapped(a.show) // left click on the icon

	go func() {
		for {
			select {
			case <-open.ClickedCh:
				a.show()
			case <-a.panic.ClickedCh:
				a.togglePanic()
			case <-restart.ClickedCh:
				go a.restartService(false)
			case <-restartAll.ClickedCh:
				go a.restartService(true)
			case <-captive.ClickedCh:
				cmd := exec.Command(a.shunt, "-s", a.sock, "captive")
				if err := cmd.Start(); err != nil {
					a.notifier.Notify(desktopapp.Notification{Summary: "Wi-Fi login", Body: err.Error()})
				} else {
					go func() {
						if err := cmd.Wait(); err != nil {
							a.notifier.Notify(desktopapp.Notification{Summary: "Wi-Fi login browser", Body: err.Error()})
						}
					}()
				}
			case <-a.autostart.ClickedCh:
				on := !a.autostart.Checked()
				if err := desktopapp.SetAutostart(on, a.exe); err != nil {
					a.notifier.Notify(desktopapp.Notification{Summary: "Autostart", Body: err.Error()})
					continue
				}
				if on {
					a.autostart.Check()
				} else {
					a.autostart.Uncheck()
				}
			case <-quit.ClickedCh:
				windowQuit()
				systray.Quit()
				os.Exit(0)
			}
		}
	}()
	go a.poll()
}

// restartService asks shuntd to restart and waits until it answers again;
// with app, this program then replaces itself with a fresh copy.
func (a *trayApp) restartService(app bool) {
	if err := a.client.Do("POST", "/v1/restart", nil, nil); err != nil {
		a.notifier.Notify(desktopapp.Notification{Summary: "Service not restarted", Body: err.Error()})
		return
	}
	time.Sleep(time.Second)
	back := false
	for i := 0; i < 30 && !back; i++ {
		var st api.Status
		back = a.client.Do("GET", "/v1/status", nil, &st) == nil
		if !back {
			time.Sleep(time.Second)
		}
	}
	if !back {
		a.notifier.Notify(desktopapp.Notification{Summary: "The Shunt service did not come back", Body: "Check: journalctl -u shuntd -e", Urgent: true})
		return
	}
	a.notifier.Notify(desktopapp.Notification{Summary: "The Shunt service restarted"})
	if app {
		args := []string{a.exe, "-s", a.sock}
		if !windowVisible() {
			args = append(args, "--hidden")
		}
		systray.Quit()
		if err := syscall.Exec(a.exe, args, os.Environ()); err != nil {
			a.notifier.Notify(desktopapp.Notification{Summary: "App not restarted", Body: err.Error()})
		}
	}
}

var lastPanic bool

func (a *trayApp) togglePanic() {
	on := !lastPanic
	// lifting panic needs the admin password (polkit dialog), setting it never does
	if err := a.client.Do("POST", "/v1/panic", api.PanicRequest{On: on}, nil); err != nil {
		a.notifier.Notify(desktopapp.Notification{Summary: "Panic mode not changed", Body: err.Error(), Urgent: true})
	}
}

func (a *trayApp) poll() {
	var prev desktopapp.View
	first := true
	for {
		var st api.Status
		err := a.client.Do("GET", "/v1/status", nil, &st)
		var sp *api.Status
		if err == nil {
			sp = &st
		}
		v := desktopapp.Compute(sp, err, time.Now())
		for _, n := range desktopapp.Diff(prev, v, first) {
			a.notifier.Notify(n)
		}
		a.render(v)
		prev, first = v, false
		time.Sleep(3 * time.Second)
	}
}

func (a *trayApp) render(v desktopapp.View) {
	systray.SetIcon(desktopapp.Icon(v.Level))
	systray.SetTooltip("The Shunt – " + v.Title)
	a.title.SetTitle(v.Title)
	lastPanic = v.Panic
	if v.Panic {
		a.panic.SetTitle("Release panic (needs admin password)")
	} else {
		a.panic.SetTitle("PANIC – block all traffic")
	}
	for i, it := range a.tunnels {
		if i < len(v.Tunnels) {
			mark := "✔ "
			if !v.Tunnels[i].OK {
				mark = "✖ "
			}
			it.SetTitle(mark + v.Tunnels[i].Text)
			it.Show()
		} else {
			it.Hide()
		}
	}
}
