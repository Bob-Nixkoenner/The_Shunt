// Command shuntd is the privileged Shunt daemon.
package main

import (
	"bufio"
	"encoding/json"

	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/Bob-Nixkoenner/the_shunt/internal/probe"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/Bob-Nixkoenner/the_shunt/internal/daemon"
	"github.com/Bob-Nixkoenner/the_shunt/internal/dnsproxy"
	"github.com/Bob-Nixkoenner/the_shunt/internal/nft"
)

// version is set at build time (-ldflags "-X main.version=…").
var version = "dev"

const usage = `usage: shuntd [-c config] <command>

commands:
  run        start the daemon (default)
  check      validate config and print the nftables ruleset, change nothing
  lockdown   block all traffic except loopback/DHCP until 'run' applies a plan
  cleanup    remove all Shunt rules, routes and tables (lifts kill switches!)
  fix-nsswitch      stop glibc from bypassing DNS routing via systemd-resolved
  restore-nsswitch  undo fix-nsswitch
  version    print the version
`

func main() {
	cfgPath := flag.String("c", config.DefaultPath, "config file")
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.Parse()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	cmd := flag.Arg(0)
	if cmd == "" {
		cmd = "run"
	}
	var err error
	switch cmd {
	case "run":
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		err = (&daemon.Daemon{ConfigPath: *cfgPath, Log: log, Version: version}).Run(ctx)
		if errors.Is(err, daemon.ErrRestart) {
			log.Info("exiting for restart (systemd starts shuntd again)")
			os.Exit(75)
		}
	case "check":
		var root string
		if b := daemon.DefaultBackend(); b != nil {
			root, _ = b.CgroupOf(os.Getpid())
		}
		var p *daemon.Prepared
		if p, err = daemon.Prepare(*cfgPath, root); err == nil {
			fmt.Print(p.Ruleset)
			for route, ups := range p.DNSUpstreams {
				for _, u := range ups {
					fmt.Fprintf(os.Stderr, "dns %s -> %s://%s\n", route, u.Proto, u.Addr)
				}
			}
			if p.DirectSystem {
				fmt.Fprintln(os.Stderr, "dns direct ->", dnsproxy.NewSystemUpstream(0).String())
			}
			for _, w := range p.Warnings {
				fmt.Fprintln(os.Stderr, "WARNING:", w)
			}
		}
	case "lockdown":
		err = nft.Apply(nft.RenderLockdown())
	case "cleanup":
		err = daemon.Cleanup()
	case "fix-nsswitch":
		var changed bool
		if changed, err = daemon.FixNsswitch(); err == nil && changed {
			fmt.Println("nsswitch.conf updated (backup: /etc/nsswitch.conf.shunt-backup)")
		} else if err == nil {
			fmt.Println("nsswitch.conf needs no change")
		}
	case "version":
		fmt.Println(version)
	case "probe": // internal: started by the daemon, which moves it into a route
		// and then says go; nothing is sent before that
		if _, err = bufio.NewReader(os.Stdin).ReadString('\n'); err == nil {
			err = json.NewEncoder(os.Stdout).Encode(probe.Run(context.Background()))
		}
	case "restore-nsswitch":
		err = daemon.RestoreNsswitch()
	default:
		flag.Usage()
		os.Exit(2)
	}
	if err != nil {
		log.Error(cmd+" failed", "err", err)
		os.Exit(1)
	}
}
