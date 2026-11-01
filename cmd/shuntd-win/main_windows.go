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
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"golang.zx2c4.com/wireguard/conn"

	"github.com/Bob-Nixkoenner/the_shunt/internal/api"
	"github.com/Bob-Nixkoenner/the_shunt/internal/blocklist"
	"github.com/Bob-Nixkoenner/the_shunt/internal/clockcheck"
	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/Bob-Nixkoenner/the_shunt/internal/netdetect"
	"github.com/Bob-Nixkoenner/the_shunt/internal/socks"
	"github.com/Bob-Nixkoenner/the_shunt/internal/splitstack"
	"github.com/Bob-Nixkoenner/the_shunt/internal/tunnel"
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
		winsplit.DisableDNSGuard()
		fmt.Println("kill switch and DNS guard lifted")
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

// resumed: the machine woke up (power event); runCore restarts the tunnel sessions.
var resumed = make(chan struct{}, 1)

const (
	pbtResumeSuspend   = 7  // PBT_APMRESUMESUSPEND: woken by the user
	pbtResumeAutomatic = 18 // PBT_APMRESUMEAUTOMATIC: woken (any reason, also from hibernation)
)

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
	st <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPowerEvent}
	for {
		select {
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				st <- c.CurrentStatus
			case svc.PowerEvent:
				if c.EventType == pbtResumeSuspend || c.EventType == pbtResumeAutomatic {
					select {
					case resumed <- struct{}{}:
					default:
					}
				}
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
	// The kill switch follows [daemon] kill_switch at once, also when edited
	// in the window. It needs the adapter's LUID, so it goes on once the
	// adapter is up; until then the persistent filters of an earlier run keep
	// blocking (the service itself may send).
	var ksMu sync.Mutex
	ksOn, ksWant := false, false
	var ksApps []string // programs that carry a Tor tunnel (tor.exe, transports)
	var ksLUID uint64
	applyKS := func() {
		ksMu.Lock()
		defer ksMu.Unlock()
		switch {
		case ksWant && !ksOn && ksLUID != 0:
			if err := winsplit.EnableKillSwitch(ksLUID, netip.MustParseAddr(splitstack.DNSAddr), ksApps...); err != nil {
				log.Printf("kill switch: %v", err)
				return
			}
			ksOn = true
			log.Print("kill switch on")
		case !ksWant && ksOn:
			winsplit.DisableKillSwitch()
			ksOn = false
			log.Print("kill switch off")
		}
	}
	var torRuns []*tunnel.Tor
	var torMu sync.Mutex
	torByName := map[string]*tunnel.Tor{} // for the status: tor's progress per tunnel
	// SOCKS5 exits of tunnels ("socks = ..."): programs that speak SOCKS can
	// use a tunnel directly; the engine dials, nothing leaves the tunnel
	var (
		socksMu  sync.Mutex
		socksCfg *config.Config
		eng      *splitstack.Engine
		sm       = &socks.Manager{Log: slog.Default()}
	)
	// inbound protection ([inbound], mode per network profile): WFP filters
	// that block new connections from the network; off unless enabled
	var inNetwork atomic.Value
	inNetwork.Store("")
	var inMu sync.Mutex
	inboundOn := false
	applyInbound := func() {
		inMu.Lock()
		defer inMu.Unlock()
		socksMu.Lock()
		c := socksCfg
		socksMu.Unlock()
		ksMu.Lock()
		luid := ksLUID
		ksMu.Unlock()
		if c == nil || luid == 0 {
			return
		}
		a := winsvc.InboundFor(c, inNetwork.Load().(string))
		if !a.On {
			if inboundOn {
				winsplit.DisableInbound()
				inboundOn = false
				log.Print("inbound protection off")
			}
			return
		}
		var ports []winsplit.InboundPort
		for _, p := range a.Ports {
			ports = append(ports, winsplit.InboundPort{TCP: p.Proto == "tcp", From: p.From, To: p.To})
		}
		if err := winsplit.EnableInbound(a.LAN, ports, luid); err != nil {
			log.Printf("inbound protection: %v", err)
			return
		}
		inboundOn = true
		log.Printf("inbound protection on (lan=%v, %d open ports)", a.LAN, len(ports))
	}
	applySocks := func() {
		socksMu.Lock()
		defer socksMu.Unlock()
		if eng == nil || socksCfg == nil {
			return
		}
		exits := map[string]socks.Exit{}
		for name, t := range socksCfg.Tunnels {
			if t.Socks == "" || t.Disabled {
				continue
			}
			route := "tunnel:" + name
			exits[name] = socks.Exit{Listen: t.Socks, Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return eng.DialRoute(ctx, route, network, addr)
			}}
		}
		sm.Update(exits)
	}
	defer sm.Close()
	defer func() {
		inMu.Lock()
		if inboundOn {
			winsplit.DisableInbound()
		}
		inMu.Unlock()
	}()
	m := &winsvc.Manager{Dir: dataDir, StatsPath: filepath.Join(dataDir, "stats.json"), Secure: lockDown,
		OnConfig: func(c *config.Config) {
			ksMu.Lock()
			ksWant = c.Daemon.KillSwitchOn()
			socksMu.Lock()
			socksCfg = c
			socksMu.Unlock()
			applySocks()
			go applyInbound()
			ksApps = nil
			for _, t := range c.Tunnels {
				if t.IsTor() && !t.Disabled {
					ksApps = tunnel.TorApps()
					break
				}
			}
			ksMu.Unlock()
			applyKS()
		}}
	m.HaveTor = func() bool { return tunnel.FindTor() != "" }
	m.StartTor = func(name string, t config.Tunnel) (string, error) {
		tr, err := tunnel.StartTor(tunnel.TorSpec{Name: name, DataDir: filepath.Join(dataDir, "tor", name),
			Bridges: t.Bridges, Isolate: t.Isolate}, slog.Default(), nil)
		if err != nil {
			return "", err
		}
		torRuns = append(torRuns, tr)
		torMu.Lock()
		torByName[name] = tr
		torMu.Unlock()
		return tr.SocksAddr(), nil
	}
	defer func() {
		for _, tr := range torRuns {
			tr.Down()
		}
	}()
	cfg, warns, err := m.Load()
	if err != nil {
		return fmt.Errorf("%s: %w", filepath.Join(dataDir, "shunt.toml"), err)
	}
	for _, w := range warns {
		log.Print("config: ", w)
	}
	// the real network first: direct traffic and the tunnels' sockets leave
	// through it (at boot the service may start before the network is up)
	up, err := waitUplink(ctx, 2*time.Minute)
	if err != nil {
		return err
	}
	var phys atomic.Uint32
	phys.Store(up.Index)
	ad, err := winsplit.OpenAdapter(splitstack.DNSAddr)
	if err != nil {
		return err
	}
	defer ad.Close()
	log.Printf("shuntd-win %s: adapter %q up, uplink %s (%s, index %d)", version, winsplit.AdapterName, up.Name, up.Link, up.Index)
	ksMu.Lock()
	ksLUID = ad.LUID()
	if !ksWant {
		winsplit.DisableKillSwitch() // left by an earlier run or version
	}
	ksMu.Unlock()
	applyKS()
	applyInbound()
	if err := winsplit.EnableDNSGuard(netip.MustParseAddr(splitstack.DNSAddr)); err != nil {
		log.Printf("DNS guard: %v (Windows may still ask the network's DNS servers directly)", err)
	}

	link, stopLink := splitstack.TunLink(ad.Dev, winsplit.MTU)
	defer stopLink()
	// processes started in a route (shunt-desktop run --via): kept across restarts
	_ = os.MkdirAll(filepath.Join(dataDir, "state"), 0o755)
	jobs := &winsplit.Jobs{State: filepath.Join(dataDir, "state", "jobs.json")}
	jobs.Load()
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				jobs.Cleanup()
			}
		}
	}()
	e, err := splitstack.New(splitstack.Options{
		Link:       link,
		Owner:      winsplit.NewOwners(jobs).Owner,
		Log:        func(s string) { log.Print(s) },
		DialDirect: winsplit.DialDirect(phys.Load),
		BindUp: func(b conn.Bind) error {
			s, ok := b.(conn.BindSocketToInterface)
			if !ok {
				return errors.New("WireGuard bind cannot be pinned to an interface")
			}
			if err := s.BindSocketToInterface4(phys.Load(), false); err != nil {
				return err
			}
			return s.BindSocketToInterface6(phys.Load(), false)
		},
	}, cfg)
	if err != nil {
		return err
	}
	defer e.Stop()
	socksMu.Lock()
	eng = e
	socksMu.Unlock()
	applySocks()
	var netInfo atomic.Value // netdetect.Info
	netInfo.Store(netdetect.Info{})
	watchStop := make(chan struct{})
	defer close(watchStop)
	go watchUplink(e, up, &phys, &netInfo, watchStop, func(n string) { inNetwork.Store(n); applyInbound() })
	go func() {
		for {
			select {
			case <-watchStop:
				return
			case <-resumed:
				e.Resumed()
			}
		}
	}()

	// DNS filter: lists are downloaded the way apps without a rule go (the
	// default route, through its tunnel and its DNS; direct only when the
	// default is direct) and cached next to the config.
	fm := &blocklist.Manager{
		Dir: filepath.Join(dataDir, "blocklists"),
		Log: slog.Default(),
		Client: func() *http.Client {
			return &http.Client{Timeout: 2 * time.Minute, Transport: &http.Transport{
				DialContext: e.DialDefault, Proxy: nil, TLSHandshakeTimeout: 15 * time.Second}}
		},
		OnChange: func(f *blocklist.Filter) { e.SetFilter(f, m.FilterLevel()) },
	}
	m.Filter = fm
	m.ApplyFilter()
	go fm.Run(ctx)

	// clock check (opt-in: [daemon] clock_check): the time as web servers
	// show it, asked through the default route
	var clockMu sync.Mutex
	var clockWarn string
	go func() {
		t := time.NewTicker(10 * time.Minute)
		defer t.Stop()
		for first := true; ; first = false {
			if !first {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
				}
			} else {
				select {
				case <-ctx.Done():
					return
				case <-time.After(30 * time.Second):
				}
			}
			socksMu.Lock()
			on := socksCfg != nil && socksCfg.Daemon.ClockCheck
			socksMu.Unlock()
			msg := ""
			if on {
				cctx, cancel := context.WithTimeout(ctx, 40*time.Second)
				cl := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{DialContext: e.DialDefault, Proxy: nil, TLSHandshakeTimeout: 15 * time.Second}}
				off, err := clockcheck.Median(cctx, cl, clockcheck.Sites)
				cancel()
				if err == nil && clockcheck.Skewed(off, 90*time.Second) {
					dir := "ahead of"
					if off > 0 {
						dir = "behind"
					}
					msg = fmt.Sprintf("the system clock is %s %s the time seen through the default route: handshakes and certificate checks may fail (turn on automatic time in Windows settings)", (off.Abs() / time.Second * time.Second).String(), dir)
				}
			}
			clockMu.Lock()
			clockWarn = msg
			clockMu.Unlock()
		}
	}()

	restart := make(chan struct{}, 1)
	m.SetRules = e.SetRules
	m.Restart = func() {
		select {
		case restart <- struct{}{}:
		default:
		}
	}
	s := &winsvc.Server{Core: e, Warnings: func() []string {
		clockMu.Lock()
		defer clockMu.Unlock()
		if clockWarn == "" {
			return nil
		}
		return []string{clockWarn}
	}, Version: version, Cfg: m, Reload: m.Reload, Restart: m.Restart,
		NetInfo: func() netdetect.Info { return netInfo.Load().(netdetect.Info) },
		TorBootstrap: func(name string) (int, bool) {
			torMu.Lock()
			tr := torByName[name]
			torMu.Unlock()
			if tr == nil {
				return 0, false
			}
			return tr.Bootstrap(), true
		},
		Pin: func(pid int, route string) error { return jobs.Pin(uint32(pid), route) },
		Procs: func(name string) ([]api.ProcRoute, error) {
			ps, err := winsplit.Processes(name)
			out := make([]api.ProcRoute, 0, len(ps))
			for _, p := range ps {
				out = append(out, api.ProcRoute{PID: int(p.PID), Name: strings.ToLower(p.Exe), Route: jobs.Route(p.PID)})
			}
			return out, err
		}}
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
		// The kill switch and the DNS guard stay while the service is stopped,
		// also at shutdown (otherwise everything leaks at the next boot until
		// the service runs). Only kill_switch = false, "shuntd-win
		// killswitch-off" or uninstalling lift them. Without the kill switch
		// the DNS guard goes: it would only break name resolution.
		ksMu.Lock()
		on := ksOn
		ksMu.Unlock()
		if !on {
			winsplit.DisableDNSGuard()
		} else {
			log.Print("kill switch stays (service stopped)")
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

// waitUplink waits until the machine has a network connection.
func waitUplink(ctx context.Context, max time.Duration) (winsplit.Uplink, error) {
	deadline := time.Now().Add(max)
	for {
		up, err := winsplit.FindUplink()
		if err == nil {
			return up, nil
		}
		if time.Now().After(deadline) {
			return up, fmt.Errorf("no network connection after %s: %w", max, err)
		}
		select {
		case <-ctx.Done():
			return up, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// watchUplink follows the network: when the real interface changes (Wi-Fi
// to cable, new Wi-Fi) direct sockets and the tunnels move to it, and the
// network profile (by Wi-Fi name and router MAC) is chosen again.
func watchUplink(e *splitstack.Engine, up winsplit.Uplink, phys *atomic.Uint32, info *atomic.Value, stop <-chan struct{}, onNet func(name string)) {
	// the router's MAC is looked up once per network (an ARP request may
	// take a moment), not on every poll
	mac := winsplit.GatewayMAC(up.Gateway)
	publish := func(u winsplit.Uplink) {
		info.Store(netdetect.Info{Iface: u.Name, SSID: u.SSID, GatewayIP: u.Gateway, GatewayMAC: mac})
	}
	publish(up)
	e.SetSystemDNS(up.DNS)
	name := e.SetNetworkMAC(up.Link, up.SSID, mac)
	if name != "" {
		log.Printf("network profile %q", name)
	}
	onNet(name)
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
		}
		cur, err := winsplit.FindUplink()
		if err != nil {
			continue // offline: keep what we have; sockets come back with the network
		}
		if cur.Index != up.Index {
			phys.Store(cur.Index)
			log.Printf("network changed: %s (%s) -> %s (%s)", up.Name, up.Link, cur.Name, cur.Link)
			e.NetworkChanged()
		}
		if cur.Key() != up.Key() || cur.Link != up.Link {
			if cur.Index != up.Index || cur.Gateway != up.Gateway || cur.SSID != up.SSID || mac == "" {
				mac = winsplit.GatewayMAC(cur.Gateway)
			}
			publish(cur)
			e.SetSystemDNS(cur.DNS)
			name := e.SetNetworkMAC(cur.Link, cur.SSID, mac)
			if name != "" {
				log.Printf("network profile %q", name)
			}
			onNet(name)
		}
		up = cur
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
	winsplit.DisableDNSGuard()
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
