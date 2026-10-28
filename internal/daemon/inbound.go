package daemon

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/Bob-Nixkoenner/the_shunt/internal/api"
	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
)

// The inbound protection asks once per unknown network; "keep closed"
// answers are kept here (next to stats.json), so it does not ask again.
func (d *Daemon) inboundClosedPath() string {
	return filepath.Join(filepath.Dir(d.statsPath()), "inbound-closed.json")
}

func netKey(ssid, mac string) string { return ssid + "|" + strings.ToLower(mac) }

func (d *Daemon) inboundClosed() []string {
	var keys []string
	if b, err := os.ReadFile(d.inboundClosedPath()); err == nil {
		_ = json.Unmarshal(b, &keys)
	}
	return keys
}

// inboundAsk returns the question for the network we are on, or nil.
// Caller holds d.mu.
func (d *Daemon) inboundAsk() *api.InboundAsk {
	if d.plan == nil || d.plan.Inbound == nil || d.prep.Network != "" {
		return nil
	}
	n := d.netInfo
	if n.SSID == "" && n.GatewayMAC == "" {
		return nil // nothing to recognize it by again
	}
	if slices.Contains(d.inboundClosed(), netKey(n.SSID, n.GatewayMAC)) {
		return nil
	}
	return &api.InboundAsk{SSID: n.SSID, GatewayMAC: n.GatewayMAC}
}

// decideInbound carries out an answer. "home" writes a profile and
// reloads; the caller has checked that the peer may manage.
func (d *Daemon) decideInbound(req api.InboundDecision) error {
	if req.SSID == "" && req.GatewayMAC == "" {
		return fmt.Errorf("ssid or gateway_mac missing")
	}
	switch req.Action {
	case "closed":
		keys := d.inboundClosed()
		if k := netKey(req.SSID, req.GatewayMAC); !slices.Contains(keys, k) {
			keys = append(keys, k)
		}
		b, _ := json.Marshal(keys)
		return writeAtomic(d.inboundClosedPath(), b, 0o600)
	case "home":
	default:
		return fmt.Errorf("action %q (home | closed)", req.Action)
	}
	d.mu.Lock()
	cfg := d.cfg
	d.mu.Unlock()
	name := req.Name
	if name == "" {
		name = profileName(req.SSID, req.GatewayMAC, cfg)
	}
	if strings.TrimSpace(name) == "" || len(name) > 40 {
		return fmt.Errorf("invalid profile name %q", name)
	}
	for _, n := range cfg.Networks {
		if n.Name == name {
			return fmt.Errorf("a network profile %q exists already", name)
		}
	}
	old, err := os.ReadFile(d.ConfigPath)
	if err != nil {
		return err
	}
	_, err = d.saveConfig(appendNetwork(old, name, req.SSID, req.GatewayMAC, cfg.Daemon.DefaultRoute), fileVersion(old))
	return err
}

// appendNetwork adds a [[network]] table at the end of a config file. The
// default route stays what it is: trusting a network for incoming
// connections says nothing about where your traffic should go.
func appendNetwork(raw []byte, name, ssid, mac, route string) []byte {
	var b strings.Builder
	b.Write(raw)
	if len(raw) > 0 && raw[len(raw)-1] != '\n' {
		b.WriteByte('\n')
	}
	b.WriteString("\n# added by the inbound protection (\"trust this network\")\n[[network]]\n")
	fmt.Fprintf(&b, "name = %s\n", strconv.Quote(name))
	if ssid != "" {
		fmt.Fprintf(&b, "ssid = [%s]\n", strconv.Quote(ssid))
	}
	if mac != "" {
		// the gateway's MAC: an SSID alone is easy to fake
		fmt.Fprintf(&b, "gateway_mac = [%s]\n", strconv.Quote(strings.ToLower(mac)))
	}
	if route == "" {
		route = "direct"
	}
	fmt.Fprintf(&b, "default_route = %s\ninbound = \"lan\"\n", strconv.Quote(route))
	return []byte(b.String())
}

var notName = regexp.MustCompile(`[^a-z0-9-]+`)

// profileName makes a profile name from the SSID ("Cafe_5G" ->
// "cafe-5g"), unique among the existing ones.
func profileName(ssid, mac string, c *config.Config) string {
	base := strings.Trim(notName.ReplaceAllString(strings.ToLower(ssid), "-"), "-")
	if base == "" {
		base = "lan-" + strings.ReplaceAll(strings.ToLower(mac), ":", "")
	}
	if len(base) > 24 {
		base = strings.TrimRight(base[:24], "-")
	}
	name := base
	for i := 2; slices.ContainsFunc(c.Networks, func(n config.Network) bool { return n.Name == name }); i++ {
		name = base + "-" + strconv.Itoa(i)
	}
	return name
}
