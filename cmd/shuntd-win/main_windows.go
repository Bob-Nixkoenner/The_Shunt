// Command shuntd-win is the Shunt service for Windows (docs/WINDOWS.md):
// the wintun adapter "Shunt" plus the splitstack engine, controlled through
// the same /v1 API as shuntd on Linux.
//
//	shuntd-win install     register the service (automatic start), as Administrator
//	shuntd-win uninstall   remove it
//	shuntd-win start|stop
//	shuntd-win run         run in this console (Ctrl+C stops), as Administrator
//
// Files live in C:\ProgramData\Shunt: shunt.toml (the config of the Linux
// daemon and its web UI), tunnels\ (WireGuard/OpenVPN files, readable by
// Administrators and SYSTEM only), shuntd.sock (API), stats.json, shuntd.log.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"golang.zx2c4.com/wireguard/conn"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/Bob-Nixkoenner/the_shunt/internal/splitstack"
	"github.com/Bob-Nixkoenner/the_shunt/internal/winsplit"
	"github.com/Bob-Nixkoenner/the_shunt/internal/winsvc"
)

const svcName = "Shunt"

// version is set at build time (-ldflags "-X main.version=…").
var version = "dev"

var dataDir = filepath.Join(os.Getenv("ProgramData"), "Shunt")

func sockPath() string { return filepath.Join(dataDir, "shuntd.sock") }

func main() {
	cmd := "run"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	if isSvc, _ := svc.IsWindowsService(); isSvc {
		cmd = "service"
	}
	var err error
	switch cmd {
	case "service":
		setupLog()
		err = svc.Run(svcName, &handler{})
	case "run":
		setupLog()
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		err = runCore(ctx, nil)
	case "install":
		err = install()
	case "uninstall":
		err = uninstall()
	case "start":
		err = control(func(s *mgr.Service) error { return s.Start() })
	case "stop":
		err = control(func(s *mgr.Service) error { _, e := s.Control(svc.Stop); return e })
	case "killswitch-off": // emergency: lift the firewall rules and policy
		winsplit.DisableKillSwitch()
		fmt.Println("kill switch lifted")
	case "version":
		fmt.Println(version)
	default:
		fmt.Fprintln(os.Stderr, "usage: shuntd-win install|uninstall|start|stop|run|killswitch-off|version")
		os.Exit(2)
	}
	if err != nil {
		log.Printf("%s failed: %v", cmd, err)
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// setupLog writes to shuntd.log (and to the console when there is one).
func setupLog() {
	log.SetFlags(log.Ldate | log.Ltime)
	_ = os.MkdirAll(dataDir, 0o755)
	f, err := os.OpenFile(filepath.Join(dataDir, "shuntd.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err == nil {
		log.SetOutput(logWriter{f})
	}
}

// logWriter writes to the log file and, best effort, to the console. A
// service has no valid stderr; io.MultiWriter would stop at that error and
// the file would stay empty.
type logWriter struct{ f *os.File }

func (w logWriter) Write(p []byte) (int, error) {
	_, _ = os.Stderr.Write(p)
	return w.f.Write(p)
}

// handler is the Service Control Manager side.
type handler struct{}

func (*handler) Execute(_ []string, req <-chan svc.ChangeRequest, st chan<- svc.Status) (bool, uint32) {
	st <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	ready := make(chan struct{})
	go func() { done <- runCore(ctx, func() { close(ready) }) }()
	select {
	case <-ready:
	case err := <-done:
		cancel()
		log.Printf("start failed: %v", err)
		return false, 1
	}
	st <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				st <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				st <- svc.Status{State: svc.StopPending}
				cancel()
				<-done
				return false, 0
			}
		case err := <-done: // stopped by the API (restart) or died
			cancel()
			if err != nil {
				log.Printf("stopped: %v", err)
				return false, 1 // non-zero: the recovery action restarts the service
			}
			return false, 1 // /v1/restart: also exit with an error so the SCM restarts us
		}
	}
}

// runCore brings everything up and blocks until ctx ends or the API asks for
// a restart. ready (may be nil) is called once the API answers.
func runCore(ctx context.Context, ready func()) error {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return err
	}
	exe, _ := os.Executable()
	ksOn := false
	m := &winsvc.Manager{Dir: dataDir, StatsPath: filepath.Join(dataDir, "stats.json"), Secure: lockDown,
		// [daemon] kill_switch follows the config at once, also when edited in the window
		OnConfig: func(c *config.Config) {
			switch {
			case c.Daemon.KillSwitch && !ksOn:
				if err := winsplit.EnableKillSwitch(exe); err != nil {
					log.Printf("kill switch: %v", err)
					return
				}
				ksOn = true
				log.Print("kill switch on")
			case !c.Daemon.KillSwitch && ksOn:
				winsplit.DisableKillSwitch()
				ksOn = false
				log.Print("kill switch off")
			}
		}}
	cfg, warns, err := m.Load()
	if err != nil {
		return fmt.Errorf("%s: %w", filepath.Join(dataDir, "shunt.toml"), err)
	}
	for _, w := range warns {
		log.Print("config: ", w)
	}
	ad, err := winsplit.OpenAdapter(splitstack.DNSAddr)
	if err != nil {
		return err
	}
	defer ad.Close()
	phys := ad.Phys
	log.Printf("shuntd-win %s: adapter %q up, physical interface %d", version, winsplit.AdapterName, phys)

	link, stopLink := splitstack.TunLink(ad.Dev, winsplit.MTU)
	defer stopLink()
	e, err := splitstack.New(splitstack.Options{
		Link:       link,
		Owner:      winsplit.NewOwners().Owner,
		Log:        func(s string) { log.Print(s) },
		DialDirect: winsplit.DialDirect(func() uint32 { return phys }),
		BindUp: func(b conn.Bind) error {
			s, ok := b.(conn.BindSocketToInterface)
			if !ok {
				return errors.New("WireGuard bind cannot be pinned to an interface")
			}
			if err := s.BindSocketToInterface4(phys, false); err != nil {
				return err
			}
			return s.BindSocketToInterface6(phys, false)
		},
	}, cfg)
	if err != nil {
		return err
	}
	defer e.Stop()

	restart := make(chan struct{}, 1)
	m.SetRules = e.SetRules
	m.Restart = func() {
		select {
		case restart <- struct{}{}:
		default:
		}
	}
	s := &winsvc.Server{Core: e, Version: version, Cfg: m, Reload: m.Reload, Restart: m.Restart}
	l, err := winsvc.Listen(sockPath())
	if err != nil {
		return err
	}
	defer os.Remove(sockPath())
	grantUsers(sockPath())
	go s.Serve(l)
	defer l.Close()
	log.Printf("API on %s", sockPath())
	if ready != nil {
		ready()
	}

	select {
	case <-ctx.Done():
		log.Print("stopping")
		if ksOn { // stopped on purpose: lift it. A crash or a restart keeps it.
			winsplit.DisableKillSwitch()
			log.Print("kill switch lifted (service stopped)")
		}
		return nil
	case <-restart:
		log.Print("restart requested")
		return nil
	}
}

// grantUsers lets every local user talk to the API (reading status, panic).
// Changing the config needs write access to windows.json, which stays with
// Administrators.
func grantUsers(path string) {
	if out, err := exec.Command("icacls", path, "/grant", "*S-1-5-32-545:(M)").CombinedOutput(); err != nil {
		log.Printf("icacls %s: %v: %s", path, err, out)
	}
}

// lockDown makes dir readable for SYSTEM and Administrators only: it holds
// private keys.
func lockDown(dir string) {
	if out, err := exec.Command("icacls", dir, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F").CombinedOutput(); err != nil {
		log.Printf("icacls %s: %v: %s", dir, err, out)
	}
}

func install() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("service manager: %w (Administrator?)", err)
	}
	defer m.Disconnect()
	if s, err := m.OpenService(svcName); err == nil {
		s.Close()
		return errors.New("service already installed (uninstall first)")
	}
	s, err := m.CreateService(svcName, exe, mgr.Config{
		DisplayName: "The Shunt",
		Description: "Per-app split tunneling with WireGuard and OpenVPN",
		StartType:   mgr.StartAutomatic,
	})
	if err != nil {
		return err
	}
	defer s.Close()
	// start again 5 s after a crash, forever (the kill switch matters)
	_ = s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 5 * time.Second}}, 86400)
	_ = s.SetRecoveryActionsOnNonCrashFailures(true) // also for "stopped with exit code 1" (/v1/restart)
	fmt.Printf("installed. Config: %s (created at the first start)\nstart with: shuntd-win start\n", filepath.Join(dataDir, "shunt.toml"))
	return nil
}

func uninstall() error {
	winsplit.DisableKillSwitch()
	return control(func(s *mgr.Service) error {
		_, _ = s.Control(svc.Stop)
		time.Sleep(time.Second)
		return s.Delete()
	})
}

func control(f func(*mgr.Service) error) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("service manager: %w (Administrator?)", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(svcName)
	if err != nil {
		return fmt.Errorf("service %q: %w", svcName, err)
	}
	defer s.Close()
	return f(s)
}
