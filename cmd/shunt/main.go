// Command shunt is the unprivileged CLI for shuntd.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/api"
	"github.com/Bob-Nixkoenner/the_shunt/internal/engine"
)

const usage = `usage: shunt [-s socket] <command>

commands:
  run (--via ROUTE | --group NAME) -- CMD [ARGS...]
             start CMD with its traffic classified by ROUTE
             (direct | block | tunnel:<name>) or by group rules
  status [--json]
  reload     re-read the daemon config
  panic on|off
             drop all traffic except loopback / undo
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
	fmt.Fprintln(w, "\nGROUP\tPROCS")
	for _, g := range st.Groups {
		fmt.Fprintf(w, "%s\t%d\n", g.Name, g.Procs)
	}
	fmt.Fprintln(w, "\nRULES (first match wins)")
	for i, r := range st.Rules {
		fmt.Fprintf(w, "%d.\t%s\n", i+1, r)
	}
	fmt.Fprintf(w, "%d.\t(default) -> %s\n", len(st.Rules)+1, st.DefaultRoute)
	return w.Flush()
}
