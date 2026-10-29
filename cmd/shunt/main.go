// Command shunt is the unprivileged CLI for shuntd.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/api"
	"github.com/Bob-Nixkoenner/the_shunt/internal/check"
	"github.com/Bob-Nixkoenner/the_shunt/internal/desktop"
	"github.com/Bob-Nixkoenner/the_shunt/internal/engine"
	"github.com/Bob-Nixkoenner/the_shunt/internal/firewall"
	"github.com/Bob-Nixkoenner/the_shunt/internal/i18n"
	"github.com/Bob-Nixkoenner/the_shunt/internal/ovpnconf"
	"github.com/Bob-Nixkoenner/the_shunt/internal/probe"
	"github.com/Bob-Nixkoenner/the_shunt/internal/speedtest"
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
  check [--json]
             judge the configuration (kill switch, DNS, OpenVPN settings …);
             exit status 1 if something is bad
  pending    programs the app firewall holds back, waiting for a route
  allow ID|NAME [--via ROUTE] [--once]
             let a waiting program out (default: the default route), and
             remember it unless --once
  firewall apps | forget KEY
             stored firewall decisions / forget one (asked again next time)
  ports [--all] [--json]
             open ports: who listens, reachable from where (--all: also
             the ones only this machine can reach)
  blocks     which programs asked for names the DNS filter blocked
  inbound [trust [NAME] | keep-closed]
             incoming protection on this network; on an unknown one:
             trust it as your LAN (adds a network profile, inbound = "lan")
             or keep it closed and stop asking
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
  speedtest [--route R1,R2,...] [--rounds N] [--provider cloudflare|ndt7] [--size-mb N] [--json]
             measure latency, download and upload of each route (default: all but
             block), one after the other, in random order, N rounds (default 3),
             result = median. Contacts speed.cloudflare.com (ndt7: M-Lab, which
             publishes the measurement together with the IP).
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
	case "speedtest":
		err = speedtestCmd(c, args[1:])
	case "run":
		err = run(c, args[1:])
	case "status":
		err = status(c, args[1:])
	case "check":
		err = checkCmd(c, args[1:])
	case "pending":
		err = pendingCmd(c)
	case "allow":
		err = allowCmd(c, args[1:])
	case "firewall":
		err = firewallCmd(c, args[1:])
	case "which":
		err = which(c, args[1:])
	case "ports":
		err = ports(c, args[1:])
	case "blocks":
		err = blocks(c)
	case "inbound":
		err = inboundCmd(c, args[1:])
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
	for _, w := range noticeTexts(res.Notices, res.Warnings) {
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

func ports(c *api.Client, args []string) error {
	all, asJSON := false, false
	for _, a := range args {
		switch a {
		case "--all":
			all = true
		case "--json":
			asJSON = true
		default:
			return fmt.Errorf("usage: shunt ports [--all] [--json]")
		}
	}
	var l api.Listening
	if err := c.Do("GET", "/v1/listening", nil, &l); err != nil {
		return err
	}
	if asJSON {
		e := json.NewEncoder(os.Stdout)
		e.SetIndent("", "  ")
		return e.Encode(l)
	}
	if l.Error != "" {
		return errors.New(l.Error)
	}
	where := "unknown network (no [[network]] profile matches)"
	if l.Network != "" {
		where = "network profile " + strconv.Quote(l.Network)
	}
	fmt.Printf("%s · connected via %s · tunnels %s\n", where, orNone(l.Uplinks), orNone(l.Tunnels))
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "PROTO\tADDRESS\tREACH\tFROM NETWORK\tFROM TUNNEL\tPROGRAM\tUNIT")
	exposed, hidden := 0, 0
	for _, p := range l.Ports {
		if p.Reach == "localhost" && !all {
			hidden++
			continue
		}
		if p.Exposed && !p.Blocked {
			exposed++
		}
		reach := p.Reach
		if reach == "iface" {
			reach = strings.Join(p.Ifaces, ",")
		}
		prog := p.Owner.Name
		if len(p.Owner.Procs) > 0 && p.Owner.Procs[0] != prog && !p.Owner.Shared {
			prog += " (" + strings.Join(p.Owner.Procs, ", ") + ")"
		}
		if prog == "" {
			prog = "?"
		}
		fromNet := yesNo(p.Exposed)
		switch {
		case p.Blocked:
			fromNet = "blocked"
		case p.LANOnly:
			fromNet = "LAN only"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", p.Proto, net.JoinHostPort(p.Addr, strconv.Itoa(int(p.Port))), reach, fromNet, yesNo(p.Tunnel), prog, p.Owner.Unit)
	}
	w.Flush()
	if hidden > 0 {
		fmt.Printf("\n%d more only reachable from this machine (--all shows them)\n", hidden)
	}
	if len(l.Firewalls) > 0 {
		fmt.Printf("Other firewalls active: %s – they may block some of these already.\n", strings.Join(l.Firewalls, ", "))
	}
	switch {
	case l.Inbound == "":
		if exposed > 0 {
			fmt.Printf("%d port(s) can be reached from the network you are connected to. Incoming protection is off ([inbound] enabled = true).\n", exposed)
		}
	default:
		fmt.Printf("Incoming protection: %s on this network, tunnels closed. %d port(s) still reachable from it.\n", l.Inbound, exposed)
	}
	return nil
}

func inboundCmd(c *api.Client, args []string) error {
	var st api.Status
	if err := c.Do("GET", "/v1/status", nil, &st); err != nil {
		return err
	}
	if len(args) == 0 {
		switch {
		case st.Inbound == "":
			fmt.Println("Incoming protection is off (enable: [inbound] enabled = true in the config).")
		case st.Network != "":
			fmt.Printf("Network profile %q: incoming %s, tunnels closed.\n", st.Network, st.Inbound)
		default:
			fmt.Printf("Unknown network: incoming %s, tunnels closed.\n", st.Inbound)
		}
		if a := st.InboundAsk; a != nil {
			fmt.Printf("Not decided yet for %s (gateway %s): shunt inbound trust [NAME] | keep-closed\n", orDash(a.SSID), orDash(a.GatewayMAC))
		}
		return nil
	}
	a := st.InboundAsk
	if a == nil {
		return fmt.Errorf("nothing to decide: the network is known or already kept closed")
	}
	req := api.InboundDecision{SSID: a.SSID, GatewayMAC: a.GatewayMAC}
	switch args[0] {
	case "trust":
		req.Action = "home"
		if len(args) > 1 {
			req.Name = args[1]
		}
	case "keep-closed":
		req.Action = "closed"
	default:
		return fmt.Errorf("usage: shunt inbound [trust [NAME] | keep-closed]")
	}
	if err := c.Do("POST", "/v1/inbound/network", req, nil); err != nil {
		return err
	}
	if req.Action == "home" {
		fmt.Println("Trusted: added a network profile with inbound = \"lan\" (ports from [inbound] allow, private addresses only).")
	} else {
		fmt.Println("Kept closed; you will not be asked again on this network.")
	}
	return nil
}

func orDash(s string) string {
	if s == "" {
		return "–"
	}
	return s
}

func orNone(s []string) string {
	if len(s) == 0 {
		return "–"
	}
	return strings.Join(s, ",")
}

func yesNo(b bool) string {
	if b {
		return "YES"
	}
	return "no"
}

func blocks(c *api.Client) error {
	var st api.Status
	if err := c.Do("GET", "/v1/status", nil, &st); err != nil {
		return err
	}
	if st.DNSFilter == nil {
		fmt.Println("The DNS filter is not active.")
		return nil
	}
	by := st.DNSFilter.Stats.ByApp
	names := make([]string, 0, len(by))
	for n := range by {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool {
		return by[names[i]] > by[names[j]] || by[names[i]] == by[names[j]] && names[i] < names[j]
	})
	fmt.Printf("%d queries blocked since the service started\n", st.DNSFilter.Stats.Blocked)
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "BLOCKED\tPROGRAM")
	for _, n := range names {
		label := n
		if label == "" {
			label = "(unknown)"
		}
		fmt.Fprintf(w, "%d\t%s\n", by[n], label)
	}
	return w.Flush()
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
	for _, wn := range noticeTexts(st.Notices, st.Warnings) {
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

// speedtestCmd: shunt speedtest [--route a,b] [--rounds N] [--provider P] [--json]
func speedtestCmd(c *api.Client, args []string) error {
	fs := flag.NewFlagSet("speedtest", flag.ExitOnError)
	routes := fs.String("route", "", i18n.T("routes to test, comma separated (default: all but block)"))
	rounds := fs.Int("rounds", 3, i18n.T("rounds (1-5); the result is the median"))
	prov := fs.String("provider", speedtest.Cloudflare, i18n.T("cloudflare | ndt7"))
	sizeMB := fs.Int("size-mb", 25, i18n.T("megabytes moved per download and upload step (1-100)"))
	asJSON := fs.Bool("json", false, i18n.T("print the report as JSON"))
	_ = fs.Parse(args)
	var st api.Status
	if err := c.Do("GET", "/v1/status", nil, &st); err != nil {
		return err
	}
	o := speedtest.Options{Provider: *prov, Rounds: *rounds, Routes: st.Routes, Bytes: int64(*sizeMB) * 1_000_000}
	if *routes != "" {
		o.Routes = strings.Split(*routes, ",")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if !*asJSON {
		fmt.Fprintln(os.Stderr, i18n.T("Measuring one route after the other, in random order; this takes a few minutes. Ctrl+C stops."))
		if *prov == speedtest.NDT7 {
			fmt.Fprintln(os.Stderr, i18n.T("M-Lab publishes every NDT7 measurement together with the IP address it came from."))
		}
	}
	rep, err := speedtest.Run(ctx, c.SpeedStep, o, func(done, total int, _ *speedtest.Report) {
		if !*asJSON {
			fmt.Fprintf(os.Stderr, "\r%d/%d ", done, total)
		}
	})
	if !*asJSON {
		fmt.Fprintln(os.Stderr)
	}
	if rep == nil {
		return err
	}
	if *asJSON {
		e := json.NewEncoder(os.Stdout)
		e.SetIndent("", "  ")
		if e2 := e.Encode(rep); e2 != nil {
			return e2
		}
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "ROUTE\tPING ms\tJITTER ms\tDOWN Mbit/s\tUP Mbit/s\tEXIT IP\tRESULT")
	for _, r := range rep.Routes {
		mark := ""
		switch {
		case r.Fastest:
			mark = " " + i18n.T("(fastest)")
		case r.Slowest:
			mark = " " + i18n.T("(slowest)")
		}
		res := strings.ToUpper(r.State)
		if r.Error != "" {
			res += " " + r.Error
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s%s\n", r.Route, num(r.LatencyMs), num(r.JitterMs), num(r.DownMbit), num(r.UpMbit), dash(r.IP), res, mark)
	}
	_ = w.Flush()
	fmt.Println(i18n.T("Seed {seed}: the same seed repeats the order.", "seed", rep.Seed))
	return err
}

func num(f float64) string {
	if f <= 0 {
		return "-"
	}
	return strconv.FormatFloat(f, 'f', 1, 64)
}

// checkCmd prints what the config check found (package check). Exit status 1
// when something is "bad", so scripts and the installer can use it.
func checkCmd(c *api.Client, args []string) error {
	var st api.Status
	if err := c.Do("GET", "/v1/status", nil, &st); err != nil {
		return err
	}
	if len(args) > 0 && args[0] == "--json" {
		return json.NewEncoder(os.Stdout).Encode(st.Findings)
	}
	if len(st.Findings) == 0 {
		fmt.Println(i18n.T("No findings: the configuration looks fine."))
		return nil
	}
	bad := false
	for _, f := range st.Findings {
		kv := make([]any, 0, 2*len(f.Vals))
		for k, v := range f.Vals {
			kv = append(kv, k, v)
		}
		mark := map[string]string{check.Bad: "BAD ", check.Warn: "WARN", check.Info: "INFO"}[f.Level]
		fmt.Printf("%s  %s\n", mark, i18n.T(f.Msg, kv...))
		if f.Fix != "" {
			fmt.Printf("      %s\n", i18n.T("Change: {key}", "key", f.Fix))
		}
		bad = bad || f.Level == check.Bad
	}
	if bad {
		return fmt.Errorf("%s", i18n.T("something is bad"))
	}
	return nil
}

// noticeTexts: the daemon's warnings in the user's language; an older daemon
// sends only the English ones.
func noticeTexts(ns []check.Finding, english []string) []string {
	if len(ns) == 0 {
		return english
	}
	out := make([]string, len(ns))
	for i, n := range ns {
		out[i] = n.Local()
	}
	return out
}
