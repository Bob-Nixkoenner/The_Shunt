// Command shunt-desktop is The Shunt's desktop app: a tray icon that always
// shows whether the tunnels protect you, desktop notifications when that
// changes, and the web UI in its own window. It runs as the desktop user
// and talks to shuntd through the same API as the CLI.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"fyne.io/systray"

	"github.com/Bob-Nixkoenner/the_shunt/internal/api"
	"github.com/Bob-Nixkoenner/the_shunt/internal/desktopapp"
	"github.com/Bob-Nixkoenner/the_shunt/internal/i18n"
	"github.com/Bob-Nixkoenner/the_shunt/internal/ui"
	"github.com/Bob-Nixkoenner/the_shunt/internal/update"
)

var version = "dev"

func init() { runtime.LockOSThread() } // GTK must own the main thread

const maxTunnelItems = 8

func main() {
	sock := flag.String("s", defaultSocket, "shuntd socket")
	hidden := flag.Bool("hidden", false, "start in the tray without opening the window")
	showVersion := flag.Bool("version", false, "print the version")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	if flag.Arg(0) == "run" { // Windows launchers: start an app in a route
		if err := runIn(*sock, flag.Args()[1:]); err != nil {
			runFailed(err)
			os.Exit(1)
		}
		return
	}

	if os.Getenv("SHUNT_RESTART") != "" {
		desktopapp.WaitFree()
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
	srv := &ui.Server{Socket: *sock, Self: launcher(self, shunt), Client: client, Apps: appSource(client, self)}
	app := &trayApp{client: client, notifier: desktopapp.NewNotifier(), exe: self, shunt: shunt, sock: *sock}
	srv.Update = &update.Checker{Current: version, OnAvailable: app.updateAvailable, Installed: func() string {
		var st api.Status
		if client.Do("GET", "/v1/status", nil, &st) != nil {
			return ""
		}
		return st.Version
	}}
	app.checker = srv.Update
	if !updatesSupported {
		srv.Update = nil
	}
	// a fixed port keeps the page's origin (and with it the saved UI
	// settings) the same across restarts; a taken port falls back to a random one
	ln, _, err := srv.Listen(uiPort)
	if err != nil {
		ln, _, err = srv.Listen(0)
	}
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
			// a fresh one-time token (the window may first open hours
			// after start); the UI then uses its session cookie
			url, err := srv.LoginURL()
			if err != nil {
				log.Print(err)
				url = ""
			}
			windowShow(url)
		} else {
			windowShow("")
		}
	}
	go single.Requests(show)

	app.show = show
	go desktopapp.PromoteTrayIcon(self)
	start, end := systray.RunWithExternalLoop(app.onReady, func() {})
	start()
	defer end()

	if !*hidden {
		show()
	}
	windowMain()
}

// uiPort is the preferred port of the local web UI.
const uiPort = 47615

func sibling(self, name string) string {
	p := filepath.Join(filepath.Dir(self), name+exeSuffix)
	if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
		return p
	}
	return ""
}

type trayApp struct {
	client   *api.Client
	notifier *desktopapp.Notifier
	show     func()
	exe      string
	update   *systray.MenuItem
	checker  *update.Checker
	updOn    *systray.MenuItem
	shunt    string // CLI, for the captive portal browser
	sock     string

	title     *systray.MenuItem
	panic     *systray.MenuItem
	autostart *systray.MenuItem
	tunnels   []*systray.MenuItem
	tunSwitch []*systray.MenuItem // per tunnel: switch on/off
	tunMu     sync.Mutex
	tunLine   []desktopapp.TunnelLine
	hidden    *systray.MenuItem // "n warnings hidden" (opens the window)
	relabel   func()            // sets the texts of the fixed menu items (again)
	lang      string            // the language they are in
}

func (a *trayApp) onReady() {
	systray.SetIcon(trayIcon(desktopapp.Icon(desktopapp.Bad)))
	systray.SetTitle("The Shunt")
	systray.SetTooltip("The Shunt")
	a.title = systray.AddMenuItem("…", "")
	a.title.Disable()
	for i := 0; i < maxTunnelItems; i++ {
		it := systray.AddMenuItem("", "")
		it.Hide()
		a.tunnels = append(a.tunnels, it)
		sw := it.AddSubMenuItem("", "")
		tip := i18n.T("Off for a while, then on again by itself. Its apps stay blocked.")
		sleeps := []*systray.MenuItem{
			it.AddSubMenuItem(i18n.T("Sleep 15 minutes"), tip),
			it.AddSubMenuItem(i18n.T("Sleep 1 hour"), tip),
			it.AddSubMenuItem(i18n.T("Sleep 4 hours"), tip),
			it.AddSubMenuItem(i18n.T("Sleep 12 hours"), tip),
		}
		a.tunSwitch = append(a.tunSwitch, sw)
		go func(i int) {
			for {
				select {
				case <-sw.ClickedCh:
					a.tunnelState(i, 0)
				case <-sleeps[0].ClickedCh:
					a.tunnelState(i, sleepSeconds[0])
				case <-sleeps[1].ClickedCh:
					a.tunnelState(i, sleepSeconds[1])
				case <-sleeps[2].ClickedCh:
					a.tunnelState(i, sleepSeconds[2])
				case <-sleeps[3].ClickedCh:
					a.tunnelState(i, sleepSeconds[3])
				}
			}
		}(i)
	}
	a.hidden = systray.AddMenuItem("", "")
	a.hidden.Hide()
	systray.AddSeparator()
	open := systray.AddMenuItem("", "")
	a.panic = systray.AddMenuItem("", "")
	captive := systray.AddMenuItem("", "")
	if runtime.GOOS == "windows" {
		captive.Hide() // needs the Linux CLI
	}
	systray.AddSeparator()
	restart := systray.AddMenuItem("", "")
	restartAll := systray.AddMenuItem("", "")
	a.update = systray.AddMenuItem("", "")
	a.update.Hide()
	systray.AddSeparator()
	a.updOn = systray.AddMenuItemCheckbox("", "", update.Enabled())
	if !updatesSupported {
		a.updOn.Hide()
	}
	a.autostart = systray.AddMenuItemCheckbox("", "", desktopapp.AutostartEnabled())
	quit := systray.AddMenuItem("", "")
	// the texts are set here and again whenever the language changes
	a.relabel = func() {
		open.SetTitle(i18n.T("Open The Shunt"))
		open.SetTooltip(i18n.T("Show the window"))
		captive.SetTitle(i18n.T("Wi-Fi login page…"))
		captive.SetTooltip(i18n.T("Hotel/train Wi-Fi: open a throwaway browser that goes past the tunnels"))
		restart.SetTitle(i18n.T("Restart service"))
		restart.SetTooltip(i18n.T("Restart shuntd (asks for the admin password); tunnelled apps are blocked for a moment"))
		restartAll.SetTitle(i18n.T("Restart service and app"))
		restartAll.SetTooltip(i18n.T("Restart shuntd, then this tray app and window"))
		a.update.SetTitle(i18n.T("Update available – how to update…"))
		a.update.SetTooltip(i18n.T("Opens the window with the update"))
		a.updOn.SetTitle(i18n.T("Check for updates"))
		a.updOn.SetTooltip(i18n.T("Ask GitHub every 3 hours whether a newer version exists"))
		a.autostart.SetTitle(i18n.T("Start at login"))
		a.autostart.SetTooltip(i18n.T("Show the tray icon after login"))
		quit.SetTitle(i18n.T("Quit tray"))
		quit.SetTooltip(i18n.T("Close the tray icon and window (protection keeps running)"))
		a.lang = i18n.Current()
	}
	a.relabel()
	systray.SetOnTapped(a.show) // left click on the icon

	go func() {
		for {
			select {
			case <-open.ClickedCh:
				a.show()
			case <-a.hidden.ClickedCh:
				a.show() // the window lists them, with "Show again"
			case <-a.panic.ClickedCh:
				a.togglePanic()
			case <-a.update.ClickedCh:
				a.show() // the window shows the command with a copy button
			case <-a.updOn.ClickedCh:
				on := !a.updOn.Checked()
				if err := update.SetEnabled(on); err != nil {
					a.notifier.Notify(desktopapp.Notification{Summary: i18n.T("Update check"), Body: err.Error()})
					continue
				}
				if on {
					a.updOn.Check()
				} else {
					a.updOn.Uncheck()
					a.update.Hide()
				}
			case <-restart.ClickedCh:
				go a.restartService(false)
			case <-restartAll.ClickedCh:
				go a.restartService(true)
			case <-captive.ClickedCh:
				cmd := exec.Command(a.shunt, "-s", a.sock, "captive")
				if err := cmd.Start(); err != nil {
					a.notifier.Notify(desktopapp.Notification{Summary: i18n.T("Wi-Fi login"), Body: err.Error()})
				} else {
					go func() {
						if err := cmd.Wait(); err != nil {
							a.notifier.Notify(desktopapp.Notification{Summary: i18n.T("Wi-Fi login browser"), Body: err.Error()})
						}
					}()
				}
			case <-a.autostart.ClickedCh:
				on := !a.autostart.Checked()
				if err := desktopapp.SetAutostart(on, a.exe); err != nil {
					a.notifier.Notify(desktopapp.Notification{Summary: i18n.T("Autostart"), Body: err.Error()})
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
	if updatesSupported {
		go a.checker.Run(context.Background())
	}
}

// updateAvailable is called once per found update.
func (a *trayApp) updateAvailable(i update.Info) {
	if a.update != nil {
		a.update.Show()
	}
	a.notifier.Notify(desktopapp.Notification{Summary: i18n.T("The Shunt: update available"), Body: i18n.T("Open the tray menu → “Update available”, then “Install update” in the window.")})
}

// sleepSeconds are the sleep choices, the same as in the window: 15 min, 1, 4, 12 h.
var sleepSeconds = [4]int{900, 3600, 4 * 3600, 12 * 3600}

// tunnelState handles a click in a tunnel's submenu: sleep 0 toggles on/off,
// otherwise the tunnel sleeps for that many seconds.
func (a *trayApp) tunnelState(i int, sleep int) {
	a.tunMu.Lock()
	if i >= len(a.tunLine) {
		a.tunMu.Unlock()
		return
	}
	l := a.tunLine[i]
	a.tunMu.Unlock()
	req := api.TunnelState{State: "off"}
	switch {
	case sleep > 0 && !l.Disabled:
		req = api.TunnelState{State: "sleep", Seconds: sleep}
	case sleep > 0:
		return // sleeping an off tunnel makes no sense
	case l.Disabled:
		req.State = "on"
	}
	go func() {
		if err := a.client.Do("POST", "/v1/tunnels/"+url.PathEscape(l.Name)+"/state", req, nil); err != nil {
			a.notifier.Notify(desktopapp.Notification{Summary: i18n.T("Tunnel {name} not changed", "name", l.Name), Body: err.Error()})
		}
	}()
}

// restartService asks shuntd to restart and waits until it answers again;
// with app, this program then replaces itself with a fresh copy.
func (a *trayApp) restartService(app bool) {
	if err := a.client.Do("POST", "/v1/restart", nil, nil); err != nil {
		a.notifier.Notify(desktopapp.Notification{Summary: i18n.T("Service not restarted"), Body: err.Error()})
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
		a.notifier.Notify(desktopapp.Notification{Summary: i18n.T("The Shunt service did not come back"), Body: restartHint(), Urgent: true})
		return
	}
	a.notifier.Notify(desktopapp.Notification{Summary: i18n.T("The Shunt service restarted")})
	if app {
		args := []string{a.exe, "-s", a.sock}
		if !windowVisible() {
			args = append(args, "--hidden")
		}
		systray.Quit()
		if err := execSelf(a.exe, args); err != nil {
			a.notifier.Notify(desktopapp.Notification{Summary: i18n.T("App not restarted"), Body: err.Error()})
		}
	}
}

var lastPanic bool

func (a *trayApp) togglePanic() {
	on := !lastPanic
	// lifting panic needs the admin password (polkit dialog), setting it never does
	if err := a.client.Do("POST", "/v1/panic", api.PanicRequest{On: on}, nil); err != nil {
		a.notifier.Notify(desktopapp.Notification{Summary: i18n.T("Panic mode not changed"), Body: err.Error(), Urgent: true})
	}
}

func (a *trayApp) poll() {
	var prev desktopapp.View
	var dnsHold desktopapp.DNSHold
	var torHold desktopapp.TorHold
	var prevN desktopapp.View
	first := true
	for {
		var st api.Status
		err := a.client.Do("GET", "/v1/status", nil, &st)
		var sp *api.Status
		if err == nil {
			sp = &st
			st.DNSFailing = dnsHold.Filter(st.DNSFailing, time.Now(), desktopapp.DNSNotifyAfter)
		}
		v := desktopapp.Compute(sp, err, time.Now())
		vn := torHold.Filter(v, sp, time.Now(), desktopapp.TorNotifyAfter) // Tor bootstraps slowly
		for _, n := range desktopapp.Diff(prevN, vn, first) {
			a.notifier.Notify(n)
		}
		if (v.Captive && (first || !prev.Captive)) || v.Pending > prev.Pending {
			a.show() // the window asks how to go on
		}
		a.render(v)
		prev, prevN, first = v, vn, false
		time.Sleep(3 * time.Second)
	}
}

func (a *trayApp) render(v desktopapp.View) {
	systray.SetIcon(trayIcon(desktopapp.IconN(v.Level, v.Active)))
	if a.relabel != nil && i18n.Current() != a.lang {
		a.relabel()
	}
	systray.SetTooltip("The Shunt – " + v.Title)
	a.title.SetTitle(v.Title)
	lastPanic = v.Panic
	if v.Panic {
		a.panic.SetTitle(i18n.T("Release panic (needs admin password)"))
	} else {
		a.panic.SetTitle(i18n.T("PANIC – block all traffic"))
	}
	if v.Hidden > 0 {
		a.hidden.SetTitle(i18n.Tn(v.Hidden, "{n} warning hidden – show…", "{n} warnings hidden – show…"))
		a.hidden.SetTooltip(i18n.T("Opens the window: the list of hidden warnings, each can be shown again"))
		a.hidden.Show()
	} else {
		a.hidden.Hide()
	}
	a.tunMu.Lock()
	a.tunLine = v.Tunnels
	a.tunMu.Unlock()
	for i, it := range a.tunnels {
		if i < len(v.Tunnels) {
			mark := "✔ "
			if !v.Tunnels[i].OK {
				mark = "✖ "
			} else if v.Tunnels[i].Asleep {
				mark = "☾ " // asleep on purpose: not a check mark
			}
			it.SetTitle(mark + v.Tunnels[i].Text)
			if v.Tunnels[i].Disabled {
				a.tunSwitch[i].SetTitle(i18n.T("Switch on"))
			} else {
				a.tunSwitch[i].SetTitle(i18n.T("Switch off"))
			}
			it.Show()
		} else {
			it.Hide()
		}
	}
}
