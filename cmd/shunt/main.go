// Command shunt is the unprivileged CLI for shuntd.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/api"
	"github.com/Bob-Nixkoenner/the_shunt/internal/desktop"
	"github.com/Bob-Nixkoenner/the_shunt/internal/engine"
	"github.com/Bob-Nixkoenner/the_shunt/internal/firewall"
	"github.com/Bob-Nixkoenner/the_shunt/internal/ovpnconf"
	"github.com/Bob-Nixkoenner/the_shunt/internal/probe"
	"github.com/Bob-Nixkoenner/the_shunt/internal/ui"
	"github.com/Bob-Nixkoenner/the_shunt/internal/update"
	"golang.org/x/term"
)

// version is set at build time (-ldflags "-X main.version=…").
var version = "dev"

const usage = `usage: shunt [-s socket] <command>

commands:
  run (--via ROUTE | --group NAME) -- CMD [ARGS...]
             start CMD with its traffic classified by ROUTE
             (direct | block | tunnel:<name> | link:wifi|ethernet|mobile) or by group rules
  status [--json]
  socks      list the SOCKS5 exits of the tunnels
  tor status | newnym [tunnel]
             Tor tunnels: progress; build new circuits for new connections
  pending    programs the app firewall holds back, waiting for a route
  allow ID|NAME [--via ROUTE] [--once]
             let a waiting program out (default: the default route), and
             remember it unless --once
  firewall apps | forget KEY
             stored firewall decisions / forget one (asked again next time)
  which NAME show running processes named like NAME and the route each one takes
  rename OLD NEW
             rename a tunnel (files, rules, default route, menu entries follow)
  import FILE [--name NAME] [--via tunnel:<name>] [--dns UPSTREAM] [--user USER]
             add a WireGuard (.conf) or OpenVPN (.ovpn) tunnel; run with sudo
             for root-only files like /etc/wireguard/*.conf. --via makes it a
             second hop through that tunnel; OpenVPN logins are asked for.
  remove NAME
             delete a tunnel and its imported files (not while the default
             route, a rule or another tunnel's --via uses it)
  captive [--browser B]
             Wi-Fi login page (hotel, train): opens a throwaway browser
             that goes direct, past the tunnels
  reload     re-read the daemon config
  restart    restart shuntd (tunnels reconnect; tunnelled apps are blocked meanwhile)
  panic on|off
             drop all traffic except loopback / undo
  pass MINUTES|off
             let everything through (direct, past tunnels and blocks) for
             1-60 minutes, then back by itself; asks for the admin password
  ui [--port N] [--no-browser] [--no-update-check]
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
	socketPath = *sock
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
	case "socks":
		err = socksCmd(c)
	case "tor":
		err = torCmd(c, args[1:])
	case "pending":
		err = pendingCmd(c)
	case "allow":
		err = allowCmd(c, args[1:])
	case "firewall":
		err = firewallCmd(c, args[1:])
	case "which":
		err = which(c, args[1:])
	case "import":
		err = importTunnel(c, args[1:])
	case "remove":
		err = removeTunnel(c, args[1:])
	case "rename":
		err = renameTunnel(c, args[1:])
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
	case "restart":
		if err = c.Do("POST", "/v1/restart", nil, nil); err == nil {
			fmt.Println("shuntd restarts")
		}
	case "captive":
		err = captive(c, args[1:])
	case "panic":
		if len(args) != 2 || (args[1] != "on" && args[1] != "off") {
			flag.Usage()
			os.Exit(2)
		}
		err = c.Do("POST", "/v1/panic", api.PanicRequest{On: args[1] == "on"}, nil)
	case "pass":
		if len(args) != 2 {
			flag.Usage()
			os.Exit(2)
		}
		m := 0
		if args[1] != "off" {
			if m, err = strconv.Atoi(args[1]); err != nil || m < 1 || m > 60 {
				fmt.Fprintln(os.Stderr, "shunt: pass takes 1-60 minutes or off")
				os.Exit(2)
			}
		}
		if err = c.Do("POST", "/v1/pass", api.PassRequest{Minutes: m}, nil); err == nil && m > 0 {
			fmt.Printf("everything goes direct for %d minutes (shunt pass off ends it)\n", m)
		}
	default:
		flag.Usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "shunt:", err)
		os.Exit(1)
	}
}

// socketPath is the -s flag, for commands that start shunt again.
var socketPath string

func run(c *api.Client, args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	via := fs.String("via", "", "route: direct | block | tunnel:<name> | link:wifi|ethernet|mobile")
	group := fs.String("group", "", "named group from the config")
	placed := fs.Bool("placed", false, "")
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
	if snapApp(cmd) && !*placed {
		return runSnapCmd(c, g, cmd)
	}
	// shuntd moves *this* process (identified by SO_PEERCRED) into the
	// group's cgroup; exec keeps the PID, so the command and all its children
	// start inside it, before opening a single socket.
	if err := c.Do("POST", "/v1/run", api.RunRequest{Group: g}, nil); err != nil {
		return err
	}
	return syscall.Exec(bin, cmd, os.Environ())
}

func importTunnel(c *api.Client, args []string) error {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	name := fs.String("name", "", "tunnel name (default: from the file name)")
	via := fs.String("via", "", "second hop through this route (tunnel:<name>), or link:wifi|ethernet|mobile")
	dns := fs.String("dns", "", "DNS upstream name from the config")
	user := fs.String("user", "", "OpenVPN username (asked for if the server wants one)")
	// flags may come after the file name
	var file string
	for len(args) > 0 {
		_ = fs.Parse(args)
		if fs.NArg() == 0 {
			break
		}
		if file != "" {
			return fmt.Errorf("one file at a time")
		}
		file, args = fs.Arg(0), fs.Args()[1:]
	}
	if file == "" {
		return fmt.Errorf("usage: shunt import FILE [--name NAME] [--via tunnel:<name>] [--dns UPSTREAM] [--user USER]")
	}
	b, err := os.ReadFile(file)
	if err != nil {
		if os.IsPermission(err) {
			return fmt.Errorf("%w (root-only file: run with sudo)", err)
		}
		return err
	}
	req := api.TunnelImport{Name: *name, Conf: string(b), Via: *via, DNS: *dns, Username: *user}
	if req.Name == "" {
		req.Name = tunnelName(file)
	}
	if !strings.Contains(req.Conf, "[Interface]") {
		clean, _ := ovpnconf.Sanitize(req.Conf) // shuntd does the same and reports it
		oc, err := ovpnconf.Parse(clean, "")
		if err != nil {
			return err
		}
		if oc.NeedsAuth {
			in := bufio.NewReader(os.Stdin)
			if req.Username == "" {
				fmt.Fprint(os.Stderr, "OpenVPN username: ")
				l, _ := in.ReadString('\n')
				req.Username = strings.TrimSpace(l)
			}
			fmt.Fprint(os.Stderr, "OpenVPN password: ")
			if term.IsTerminal(int(os.Stdin.Fd())) {
				p, err := term.ReadPassword(int(os.Stdin.Fd()))
				fmt.Fprintln(os.Stderr)
				if err != nil {
					return err
				}
				req.Password = string(p)
			} else {
				l, _ := in.ReadString('\n')
				req.Password = strings.TrimRight(l, "\r\n")
			}
		}
	}
	var res api.CheckResult
	if err := c.Do("POST", "/v1/tunnels", req, &res); err != nil {
		return err
	}
	fmt.Printf("imported tunnel %q (route tunnel:%s)\n", req.Name, req.Name)
	for _, w := range res.Warnings {
		fmt.Println("warning:", w)
	}
	return nil
}

// renameTunnel renames a tunnel in the daemon, then points the menu
// launchers of this user (which carry the route name) at the new name.
func renameTunnel(c *api.Client, args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: shunt rename OLD NEW")
	}
	from, to := args[0], args[1]
	if err := c.Do("POST", "/v1/tunnels/"+url.PathEscape(from)+"/rename", api.TunnelRename{To: to}, nil); err != nil {
		return err
	}
	fmt.Printf("tunnel %q is now %q (route tunnel:%s)\n", from, to, to)
	list, err := desktop.List()
	if err != nil {
		return nil
	}
	for _, e := range list {
		if e.Route == "tunnel:"+from {
			if err := desktop.SetRoute(e.ID, "tunnel:"+to, self()); err != nil {
				fmt.Printf("warning: menu entry %s: %v\n", e.ID, err)
			} else {
				fmt.Printf("menu entry %s now starts via tunnel:%s\n", e.ID, to)
			}
		}
	}
	return nil
}

// tunnelName derives a valid tunnel name from a file name:
// "/etc/wireguard/Mullvad-DE_fra 001.conf" -> "mullvad-de".
func tunnelName(file string) string {
	base := strings.ToLower(filepath.Base(file))
	base = strings.TrimSuffix(strings.TrimSuffix(base, ".conf"), ".ovpn")
	var b strings.Builder
	for _, r := range base {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_' || r == ' ' || r == '.':
			if b.Len() > 0 {
				b.WriteByte('-')
			}
		}
	}
	n := b.String()
	if len(n) > 10 {
		n = n[:10]
	}
	n = strings.TrimRight(n, "-")
	if n == "" {
		n = "tunnel"
	}
	return n
}

func pendingCmd(c *api.Client) error {
	var ps []firewall.Pending
	if err := c.Do("GET", "/v1/pending", nil, &ps); err != nil {
		return err
	}
	if len(ps) == 0 {
		fmt.Println("no program is waiting")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tPROGRAM\tPROCS\tWAITING\tTHEN")
	for _, p := range ps {
		then := "blocked until you decide"
		if !p.Deadline.IsZero() {
			then = "default route in " + time.Until(p.Deadline).Round(time.Second).String()
		}
		fmt.Fprintf(w, "%s\t%s (%s)\t%d\t%s\t%s\n", p.ID, p.Name, p.Key, p.Procs, time.Since(p.Asked).Round(time.Second), then)
	}
	w.Flush()
	fmt.Println("\nshunt allow <ID> --via <route>   (direct | tunnel:<name> | block)")
	return nil
}

func allowCmd(c *api.Client, args []string) error {
	fs := flag.NewFlagSet("allow", flag.ExitOnError)
	via := fs.String("via", "", "route (default: the default route)")
	once := fs.Bool("once", false, "only for this run, don't remember")
	var target string
	for len(args) > 0 {
		_ = fs.Parse(args)
		if fs.NArg() == 0 {
			break
		}
		target, args = fs.Arg(0), fs.Args()[1:]
	}
	if target == "" {
		return fmt.Errorf("usage: shunt allow ID|NAME [--via ROUTE] [--once]")
	}
	var ps []firewall.Pending
	if err := c.Do("GET", "/v1/pending", nil, &ps); err != nil {
		return err
	}
	id := ""
	for _, p := range ps {
		if p.ID == target || p.Name == target {
			id = p.ID
		}
	}
	if id == "" {
		return fmt.Errorf("no waiting program %q (see shunt pending)", target)
	}
	if err := c.Do("POST", "/v1/pending/"+id, api.FirewallDecision{Route: *via, Remember: !*once}, nil); err != nil {
		return err
	}
	fmt.Printf("%s goes %s\n", target, map[bool]string{true: "via the default route", false: "via " + *via}[*via == ""])
	return nil
}

func firewallCmd(c *api.Client, args []string) error {
	switch {
	case len(args) == 1 && args[0] == "apps":
		var rs []firewall.Remembered
		if err := c.Do("GET", "/v1/firewall/apps", nil, &rs); err != nil {
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "PROGRAM\tROUTE\tKEY")
		for _, r := range rs {
			route := r.Route
			if route == "" {
				route = "(default route)"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\n", r.Name, route, r.Key)
		}
		return w.Flush()
	case len(args) == 2 && args[0] == "forget":
		return c.Do("DELETE", "/v1/firewall/apps?key="+url.QueryEscape(args[1]), nil, nil)
	}
	return fmt.Errorf("usage: shunt firewall apps | forget KEY")
}

func removeTunnel(c *api.Client, args []string) error {
	if len(args) != 1 || args[0] == "" {
		return fmt.Errorf("usage: shunt remove NAME")
	}
	name := strings.TrimPrefix(args[0], "tunnel:")
	if err := c.Do("DELETE", "/v1/tunnels/"+url.PathEscape(name), nil, nil); err != nil {
		return err
	}
	fmt.Printf("tunnel %q removed\n", name)
	return nil
}

func which(c *api.Client, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: shunt which NAME   (e.g. shunt which brave)")
	}
	var ps []api.ProcRoute
	if err := c.Do("GET", "/v1/procs?name="+url.QueryEscape(args[0]), nil, &ps); err != nil {
		return err
	}
	if len(ps) == 0 {
		fmt.Printf("no running process named like %q\n", args[0])
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "PID\tNAME\tROUTE\tGROUP")
	routes := map[string]bool{}
	for _, p := range ps {
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\n", p.PID, p.Name, p.Route, p.Group)
		routes[p.Route] = true
	}
	w.Flush()
	if len(routes) > 1 {
		fmt.Println("\nNote: this program runs in more than one route. A browser that is already")
		fmt.Println("running opens new windows in its *old* process and route: quit it completely")
		fmt.Println("(also from the tray / background) and start it again.")
	}
	return nil
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
	if st.Network != "" {
		fmt.Fprintf(w, "default route:\t%s (network profile %q)\n", st.DefaultRoute, st.Network)
	} else {
		fmt.Fprintf(w, "default route:\t%s\n", st.DefaultRoute)
	}
	if ni := st.NetInfo; ni.Iface != "" {
		where := ni.Iface
		if ni.SSID != "" {
			where += ", Wi-Fi " + strconv.Quote(ni.SSID)
		}
		if ni.GatewayMAC != "" {
			where += ", gateway " + ni.GatewayMAC
		}
		fmt.Fprintf(w, "network:\t%s\n", where)
	}
	if st.Panic {
		fmt.Fprintln(w, "PANIC MODE:\tall traffic blocked")
	}
	if st.PassLeft > 0 {
		fmt.Fprintf(w, "PASS:\teverything goes direct for %s more (shunt pass off)\n", (time.Duration(st.PassLeft) * time.Second).String())
	}
	fmt.Fprintln(w, "\nTUNNEL\tIFACE\tSTATE\tHANDSHAKE\tRX/TX")
	for _, t := range st.Tunnels {
		state := "down (blocked)"
		if t.Disabled {
			state = "off (blocked)"
		}
		if t.Up {
			state = "up/" + t.Driver
			if h := t.Health; h != nil && h.State != "unknown" {
				state += " " + h.State
				if h.LatencyMs > 0 {
					state += fmt.Sprintf(" %dms", h.LatencyMs)
				}
			}
		}
		if t.Up && t.Bootstrap != nil {
			state = "up/tor"
			if *t.Bootstrap < 100 {
				state = fmt.Sprintf("starting/tor %d%%", *t.Bootstrap)
			}
		}
		hs, rxtx := "-", "-"
		for _, p := range t.Peers {
			if !p.LastHandshake.IsZero() {
				hs = time.Since(p.LastHandshake).Round(time.Second).String() + " ago"
			}
			rxtx = fmt.Sprintf("%d/%d", p.RxBytes, p.TxBytes)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", t.Name, t.Iface, state, hs, rxtx)
		if t.Via != "" {
			fmt.Fprintf(w, "  via:\t%s (second hop)\n", t.Via)
		}
		if t.Error != "" {
			fmt.Fprintf(w, "  error:\t%s\n", t.Error)
		}
	}
	if len(st.Traffic) > 1 { // "total" plus at least one tunnel
		fmt.Fprintln(w, "\nTRAFFIC\tTHIS MONTH ↓/↑\tLAST MONTH ↓/↑\tTOTAL ↓/↑")
		names := make([]string, 0, len(st.Traffic))
		for n := range st.Traffic {
			if n != "total" {
				names = append(names, n)
			}
		}
		sort.Strings(names)
		for _, n := range append(names, "total") {
			t := st.Traffic[n]
			label := "tunnel:" + n
			if n == "total" {
				label = "all tunnels"
			}
			fmt.Fprintf(w, "%s\t%s / %s\t%s / %s\t%s / %s\n", label, humanBytes(t.Month.RX), humanBytes(t.Month.TX),
				humanBytes(t.LastMonth.RX), humanBytes(t.LastMonth.TX), humanBytes(t.Total.RX), humanBytes(t.Total.TX))
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
	if f := st.DNSFilter; f != nil {
		fmt.Fprintf(w, "\nDNS FILTER\tdefault %s, %d blocked since start\n", f.Default, f.Stats.Blocked)
		for _, l := range f.Lists {
			state := fmt.Sprintf("%d names", l.Entries)
			if l.Error != "" {
				state += ", error: " + l.Error
			}
			fmt.Fprintf(w, "  %s\t%s (%s)\n", l.Name, state, strings.Join(l.Levels, ", "))
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
	noUpdate := fs.Bool("no-update-check", false, "don't ask GitHub for a newer version")
	_ = fs.Parse(args)
	if err := c.Do("GET", "/v1/status", nil, nil); err != nil {
		return fmt.Errorf("%w\n(is shuntd running, and are you in group 'shunt'?)", err)
	}
	srv := &ui.Server{Socket: sock, Self: self(), Client: c}
	if !*noUpdate {
		srv.Update = &update.Checker{Current: version, Installed: func() string {
			var st api.Status
			if c.Do("GET", "/v1/status", nil, &st) != nil {
				return ""
			}
			return st.Version
		}}
		go srv.Update.Run(context.Background())
	}
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
	res := probe.LeakTest(ctx, c.Probe, st.Routes)
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

// humanBytes: 1.5 GB style (powers of 1000, like traffic plans count).
func humanBytes(n int64) string {
	const unit = 1000
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "kMGTPE"[exp])
}

// socksCmd lists the SOCKS5 exits of the tunnels.
func socksCmd(c *api.Client) error {
	var st api.Status
	if err := c.Do("GET", "/v1/status", nil, &st); err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	n := 0
	for _, t := range st.Tunnels {
		if t.Socks == "" {
			continue
		}
		state := "up"
		if !t.Up {
			state = "tunnel down (connections are refused)"
		}
		fmt.Fprintf(w, "tunnel:%s\tsocks5h://%s\t%s\n", t.Name, t.Socks, state)
		n++
	}
	if n == 0 {
		fmt.Fprintln(w, "no tunnel has a SOCKS5 exit; set socks = \"127.0.0.1:1080\" in its [tunnel.<name>] section")
	}
	return w.Flush()
}

// torCmd: shunt tor status | newnym [tunnel]
func torCmd(c *api.Client, args []string) error {
	var st api.Status
	if err := c.Do("GET", "/v1/status", nil, &st); err != nil {
		return err
	}
	var tors []api.TunnelStatus
	for _, t := range st.Tunnels {
		if t.Bootstrap != nil {
			tors = append(tors, t)
		}
	}
	if len(args) == 0 || (args[0] != "status" && args[0] != "newnym") {
		return errors.New("usage: shunt tor status | shunt tor newnym [tunnel]")
	}
	if len(tors) == 0 {
		return errors.New("no Tor tunnel is running (driver = \"tor\" in a [tunnel.<name>] section)")
	}
	if args[0] == "status" {
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		for _, t := range tors {
			state := "connected"
			if *t.Bootstrap < 100 {
				state = fmt.Sprintf("starting, %d%%", *t.Bootstrap)
			}
			fmt.Fprintf(w, "tunnel:%s\t%s\n", t.Name, state)
			if t.Error != "" {
				fmt.Fprintf(w, "  error:\t%s\n", t.Error)
			}
		}
		return w.Flush()
	}
	name := ""
	switch {
	case len(args) > 1:
		name = strings.TrimPrefix(args[1], "tunnel:")
	case len(tors) == 1:
		name = tors[0].Name
	default:
		return errors.New("more than one Tor tunnel: shunt tor newnym <tunnel>")
	}
	if err := c.Do("POST", "/v1/tunnels/"+url.PathEscape(name)+"/newnym", nil, nil); err != nil {
		return err
	}
	fmt.Printf("tunnel:%s builds new circuits for new connections (tor allows this once every 10 seconds)\n", name)
	return nil
}
