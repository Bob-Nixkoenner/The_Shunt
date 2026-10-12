// Command shunt is the unprivileged CLI for shuntd.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/api"
	"github.com/Bob-Nixkoenner/the_shunt/internal/desktop"
	"github.com/Bob-Nixkoenner/the_shunt/internal/engine"
	"github.com/Bob-Nixkoenner/the_shunt/internal/probe"
	"github.com/Bob-Nixkoenner/the_shunt/internal/ui"
)

// version is set at build time (-ldflags "-X main.version=…").
var version = "dev"

const usage = `usage: shunt [-s socket] <command>

commands:
  run (--via ROUTE | --group NAME) -- CMD [ARGS...]
             start CMD with its traffic classified by ROUTE
             (direct | block | tunnel:<name>) or by group rules
  status [--json]
  reload     re-read the daemon config
  panic on|off
             drop all traffic except loopback / undo
  ui [--port N] [--no-browser]
             open the web interface (local only)
  leaktest   check public IP and DNS resolver of every route
             (contacts api.ipify.org and Google DNS through each route)
  desktop list | set <app-id> <route> | unset <app-id>
             make an app's menu entry always start through a route
  desktop clone <app-id> <route> --name NAME [--args ARGS]
             extra menu entry, e.g. one per Firefox profile:
             desktop clone firefox-esr tunnel:vps --name "Firefox SM" --args "--new-instance -P sm"
  desktop profiles
             list Firefox profiles
  version
`

func main() {
	sock := flag.String("s", "/run/shunt/shuntd.sock", "shuntd socket")
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.Parse()
	c := api.NewClient(*sock)
	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
		os.Exit(2)
	}
	var err error
	switch args[0] {
	case "run":
		err = run(c, args[1:])
	case "status":
		err = status(c, args[1:])
	case "version":
		fmt.Println(version)
	case "ui":
		err = runUI(c, *sock, args[1:])
	case "probe": // internal: used by leaktest inside each route
		err = json.NewEncoder(os.Stdout).Encode(probe.Run(context.Background()))
	case "leaktest":
		err = leaktest(c, *sock)
	case "desktop":
		err = desktopCmd(args[1:])
	case "reload":
		err = c.Do("POST", "/v1/reload", nil, nil)
	case "panic":
		if len(args) != 2 || (args[1] != "on" && args[1] != "off") {
			flag.Usage()
			os.Exit(2)
		}
		err = c.Do("POST", "/v1/panic", api.PanicRequest{On: args[1] == "on"}, nil)
	default:
		flag.Usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "shunt:", err)
		os.Exit(1)
	}
}

func run(c *api.Client, args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	via := fs.String("via", "", "route: direct | block | tunnel:<name>")
	group := fs.String("group", "", "named group from the config")
	_ = fs.Parse(args)
	cmd := fs.Args()
	if len(cmd) == 0 || (*via == "") == (*group == "") {
		return fmt.Errorf("need exactly one of --via/--group and a command")
	}
	g := *group
	if *via != "" {
		g = engine.ViaGroupName(*via)
	}
	bin, err := exec.LookPath(cmd[0])
	if err != nil {
		return err
	}
	// shuntd moves *this* process (identified by SO_PEERCRED) into the
	// group's cgroup; exec keeps the PID, so the command and all its children
	// start inside it, before opening a single socket.
	if err := c.Do("POST", "/v1/run", api.RunRequest{Group: g}, nil); err != nil {
		return err
	}
	return syscall.Exec(bin, cmd, os.Environ())
}

func status(c *api.Client, args []string) error {
	var st api.Status
	if err := c.Do("GET", "/v1/status", nil, &st); err != nil {
		return err
	}
	if len(args) > 0 && args[0] == "--json" {
		e := json.NewEncoder(os.Stdout)
		e.SetIndent("", "  ")
		return e.Encode(st)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	for _, wn := range st.Warnings {
		fmt.Fprintf(w, "WARNING:\t%s\n", wn)
	}
	fmt.Fprintf(w, "default route:\t%s\n", st.DefaultRoute)
	if st.Panic {
		fmt.Fprintln(w, "PANIC MODE:\tall traffic blocked")
	}
	fmt.Fprintln(w, "\nTUNNEL\tIFACE\tSTATE\tHANDSHAKE\tRX/TX")
	for _, t := range st.Tunnels {
		state := "down (blocked)"
		if t.Up {
			state = "up/" + t.Driver
		}
		hs, rxtx := "-", "-"
		for _, p := range t.Peers {
			if !p.LastHandshake.IsZero() {
				hs = time.Since(p.LastHandshake).Round(time.Second).String() + " ago"
			}
			rxtx = fmt.Sprintf("%d/%d", p.RxBytes, p.TxBytes)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", t.Name, t.Iface, state, hs, rxtx)
		if t.Error != "" {
			fmt.Fprintf(w, "  error:\t%s\n", t.Error)
		}
	}
	if len(st.DNS) > 0 {
		fmt.Fprintln(w, "\nDNS ROUTE\tUPSTREAMS")
		routes := make([]string, 0, len(st.DNS))
		for r := range st.DNS {
			routes = append(routes, r)
		}
		sort.Strings(routes)
		for _, r := range routes {
			fmt.Fprintf(w, "%s\t%s\n", r, strings.Join(st.DNS[r], ", "))
		}
	}
	fmt.Fprintln(w, "\nGROUP\tROUTE\tPROCS\tAPPS")
	for _, g := range st.Groups {
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\n", g.Name, g.Route, g.Procs, strings.Join(g.Apps, ", "))
	}
	fmt.Fprintln(w, "\nRULES (first match wins)")
	for i, r := range st.Rules {
		fmt.Fprintf(w, "%d.\t%s\n", i+1, r)
	}
	fmt.Fprintf(w, "%d.\t(default) -> %s\n", len(st.Rules)+1, st.DefaultRoute)
	return w.Flush()
}

func self() string {
	if p, err := os.Executable(); err == nil {
		return p
	}
	return "shunt"
}

func runUI(c *api.Client, sock string, args []string) error {
	fs := flag.NewFlagSet("ui", flag.ExitOnError)
	port := fs.Int("port", 0, "port on 127.0.0.1 (0 = random)")
	noBrowser := fs.Bool("no-browser", false, "only print the address")
	_ = fs.Parse(args)
	if err := c.Do("GET", "/v1/status", nil, nil); err != nil {
		return fmt.Errorf("%w\n(is shuntd running, and are you in group 'shunt'?)", err)
	}
	srv := &ui.Server{Socket: sock, Self: self(), Client: c}
	ln, url, err := srv.Listen(*port)
	if err != nil {
		return err
	}
	fmt.Println("The Shunt UI:", url)
	fmt.Println("(keep this running; Ctrl+C to stop)")
	if !*noBrowser {
		ui.OpenBrowser(url)
	}
	return srv.Serve(ln)
}

func leaktest(c *api.Client, sock string) error {
	var st api.Status
	if err := c.Do("GET", "/v1/status", nil, &st); err != nil {
		return err
	}
	fmt.Println("Probing every route (api.ipify.org + Google DNS)...")
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	res := probe.LeakTest(ctx, self(), sock, st.Routes)
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "ROUTE\tPUBLIC IP\tDNS RESOLVER\tRESULT")
	leak := false
	for _, r := range res {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s %s\n", r.Route, dash(r.Result.IP), dash(r.Result.Resolver), strings.ToUpper(r.Verdict), r.Note)
		leak = leak || r.Verdict == "leak"
	}
	_ = w.Flush()
	if leak {
		return fmt.Errorf("LEAK detected")
	}
	return nil
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func desktopCmd(args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	switch {
	case args[0] == "list":
		list, err := desktop.List()
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "APP ID\tNAME\tROUTE")
		for _, e := range list {
			fmt.Fprintf(w, "%s\t%s\t%s\n", e.ID, e.Name, dash(e.Route))
		}
		return w.Flush()
	case args[0] == "set" && len(args) == 3:
		if err := desktop.SetRoute(args[1], args[2], self()); err != nil {
			return err
		}
		fmt.Printf("%s now starts via %s from the menu\n", args[1], args[2])
		return nil
	case args[0] == "clone" && len(args) >= 3:
		fs := flag.NewFlagSet("clone", flag.ExitOnError)
		name := fs.String("name", "", "menu name of the new entry")
		extra := fs.String("args", "", "extra arguments")
		_ = fs.Parse(args[3:])
		id, err := desktop.Clone(args[1], *name, *extra, args[2], self())
		if err != nil {
			return err
		}
		fmt.Printf("created menu entry %q (%s) via %s\n", *name, id, args[2])
		return nil
	case args[0] == "profiles":
		for _, p := range desktop.FirefoxProfiles() {
			fmt.Println(p)
		}
		return nil
	case args[0] == "unset" && len(args) == 2:
		if err := desktop.Unset(args[1]); err != nil {
			return err
		}
		fmt.Printf("%s restored to its original menu entry\n", args[1])
		return nil
	}
	return fmt.Errorf("usage: shunt desktop list | set <app-id> <route> | unset <app-id> | clone <app-id> <route> --name N [--args A] | profiles")
}
