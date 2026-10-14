// shunt-win-proto: first Windows prototype of the per-app split (see
// docs/WINDOWS.md). Run as Administrator:
//
//	shunt-win-proto.exe config.json
//
// config.json has the format of internal/splitstack (as on Android), with
// lower-case exe paths as app IDs:
//
//	{"tunnels":[{"name":"home","conf":"[Interface]\n..."}],
//	 "default":"direct",
//	 "apps":{"c:\\program files\\mozilla firefox\\firefox.exe":"tunnel:home"}}
//
// It creates the wintun adapter "Shunt" with routes 0.0.0.0/1 + 128.0.0.0/1
// (and ::/1 + 8000::/1), so all traffic enters the split; the core's own
// sockets are pinned to the physical interface. Ctrl+C removes the adapter
// and with it the routes. No kill switch, no DNS leak protection yet.
package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/splitstack"
	"github.com/Bob-Nixkoenner/the_shunt/internal/winsplit"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun"
)

const (
	adapter = "Shunt"
	mtu     = 1280
)

// cleanup runs before any exit once the adapter exists: closing it
// removes the adapter and with it its addresses and routes.
var cleanup []func()

func fatalf(f string, a ...any) {
	log.Printf(f, a...)
	for i := len(cleanup) - 1; i >= 0; i-- {
		cleanup[i]()
	}
	os.Exit(1)
}

func netsh(args ...string) {
	out, err := exec.Command("netsh", args...).CombinedOutput()
	if err != nil {
		fatalf("netsh %v: %v: %s", args, err, out)
	}
}

func main() {
	log.SetFlags(log.Ltime)
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: shunt-win-proto config.json   (as Administrator)")
		os.Exit(2)
	}
	cfg, err := os.ReadFile(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	// the physical interface: where the default route goes before ours
	var phys uint32
	if err := windows.GetBestInterfaceEx(&windows.SockaddrInet4{Addr: [4]byte{1, 1, 1, 1}}, &phys); err != nil {
		log.Fatalf("no default route: %v", err)
	}
	log.Printf("physical interface index %d", phys)

	dev, err := tun.CreateTUN(adapter, mtu)
	if err != nil {
		log.Fatalf("wintun: %v (Administrator? wintun.dll next to the exe?)", err)
	}
	cleanup = append(cleanup, func() { dev.Close() })
	netsh("interface", "ipv4", "set", "address", "name="+adapter, "static", "10.111.0.2", "255.255.255.0")
	netsh("interface", "ipv4", "set", "dnsservers", "name="+adapter, "static", splitstack.DNSAddr, "validate=no")
	netsh("interface", "ipv4", "add", "route", "0.0.0.0/1", adapter, "10.111.0.1", "metric=1")
	netsh("interface", "ipv4", "add", "route", "128.0.0.0/1", adapter, "10.111.0.1", "metric=1")
	netsh("interface", "ipv6", "add", "address", adapter, "fd11:5ee:bad:c0de::2/64")
	netsh("interface", "ipv6", "add", "route", "::/1", adapter, "fd11:5ee:bad:c0de::1", "metric=1")
	netsh("interface", "ipv6", "add", "route", "8000::/1", adapter, "fd11:5ee:bad:c0de::1", "metric=1")

	link, stop := splitstack.TunLink(dev, mtu)
	cleanup = append(cleanup, stop)
	owners := winsplit.NewOwners()
	e, err := splitstack.New(splitstack.Options{
		Link:       link,
		Owner:      owners.Owner,
		Log:        func(s string) { log.Print(s) },
		DialDirect: winsplit.DialDirect(func() uint32 { return phys }),
		BindUp: func(b conn.Bind) error {
			s, ok := b.(conn.BindSocketToInterface)
			if !ok {
				return fmt.Errorf("WireGuard bind cannot be pinned to an interface")
			}
			if err := s.BindSocketToInterface4(phys, false); err != nil {
				return err
			}
			return s.BindSocketToInterface6(phys, false)
		},
	}, string(cfg))
	if err != nil {
		fatalf("%v", err)
	}
	cleanup = append(cleanup, e.Stop)
	log.Printf("running – Ctrl+C to stop (adapter %q, physical interface %d)", adapter, phys)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM) // Ctrl+C, Ctrl+Break, closing the console
	tick := time.NewTicker(10 * time.Second)
	for {
		select {
		case <-sig:
			log.Print("stopping")
			for i := len(cleanup) - 1; i >= 0; i-- {
				cleanup[i]()
			}
			return
		case <-tick.C:
			log.Print(e.Status())
		}
	}
}
