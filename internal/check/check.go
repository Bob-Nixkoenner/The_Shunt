// Package check judges a configuration the way a reviewer would: not "does
// it load" (config.Validate does that) but "is it safe". The findings carry
// an English sentence with {placeholders} plus the values, so every front
// end (web UI, tray, CLI, Android) translates them with its own catalog and
// the sentence is never glued together from pieces.
//
// The checks that need a network (clock, leak test) are separate; this
// package works on the files alone and is the same on every platform.
package check

import (
	"cmp"
	"slices"
	"strings"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/Bob-Nixkoenner/the_shunt/internal/ovpnconf"
)

// Levels, worst first.
const (
	Bad  = "bad"  // traffic can leave unprotected, or the setting defeats Shunt
	Warn = "warn" // weak setting, worth fixing
	Info = "info" // not wrong, but you should know
)

// Finding is one result. ID is stable (tests, "ignore this one" later), Msg
// the English text with {name} placeholders filled from Vals.
type Finding struct {
	ID    string            `json:"id"`
	Level string            `json:"level"`
	Msg   string            `json:"msg"`
	Vals  map[string]string `json:"vals,omitempty"`
	// Fix names where it is changed ("" = nowhere in the UI yet), as a
	// config key: "daemon.boot_lockdown".
	Fix string `json:"fix,omitempty"`
}

// Env is what the checks need besides the config.
type Env struct {
	Windows bool // kill switch (WFP) exists; boot lockdown and NetworkManager do not
	Android bool // no NetworkManager, no boot lockdown, no inbound protection
	// OVPN returns the parsed .ovpn of a tunnel (nil = unknown).
	OVPN func(tunnel string) *ovpnconf.Config
}

func (e Env) linux() bool { return !e.Windows && !e.Android }

// Config checks c and returns the findings, worst first.
func Config(c *config.Config, env Env) []Finding {
	var out []Finding
	add := func(level, id, msg, fix string, kv ...string) {
		f := Finding{ID: id, Level: level, Msg: msg, Fix: fix}
		if len(kv) > 0 {
			f.Vals = map[string]string{}
			for i := 0; i+1 < len(kv); i += 2 {
				f.Vals[kv[i]] = kv[i+1]
			}
		}
		out = append(out, f)
	}
	hasTunnel := false
	for _, t := range c.Tunnels {
		if !t.Disabled {
			hasTunnel = true
		}
	}
	defaultDirect := strings.HasPrefix(c.Daemon.DefaultRoute, "direct") || c.Daemon.DefaultRoute == ""

	if c.DNS.Disabled {
		add(Bad, "dns.off", "DNS routing is off: DNS queries leave past the tunnels.", "dns.disabled")
	}
	if c.DNS.AllowDoH || c.DNS.AllowDoT {
		add(Warn, "dns.doh", "Encrypted DNS (DoH/DoT) is allowed: a program can resolve names past the DNS servers of its route.", "dns.allow_doh")
	}
	if env.Windows && !c.Daemon.KillSwitchOn() {
		add(Bad, "killswitch.off", "The kill switch is off: if a tunnel or the service stops, traffic can leave directly.", "daemon.kill_switch")
	}
	if env.linux() && c.Daemon.BootLockdown == "off" && hasTunnel && !defaultDirect {
		add(Warn, "bootlock.off", "The boot lockdown is off: while the computer starts, traffic meant for a tunnel can leave unprotected.", "daemon.boot_lockdown")
	}
	if hasTunnel && defaultDirect {
		add(Info, "default.direct", "The default route is direct: programs without a rule are not protected by a tunnel.", "daemon.default_route")
	}
	for _, n := range c.Networks {
		relaxed := strings.HasPrefix(n.DefaultRoute, "direct") || n.Inbound == "lan" || n.Inbound == "open"
		if relaxed && len(n.GatewayMAC) == 0 && len(n.SSID) > 0 {
			add(Warn, "network.ssid_only", "Network profile “{name}” relaxes the protection but is recognised by its Wi-Fi name alone: a fake hotspot with that name gets the same trust. Add the router's MAC (gateway_mac).",
				"network.gateway_mac", "name", n.Name)
		}
	}
	if env.linux() && (c.Daemon.MAC == "" || c.Daemon.DHCPHostname == "") {
		add(Info, "stealth.unset", "In foreign networks your real MAC address and device name are visible (daemon.mac and daemon.dhcp_hostname are not set).", "daemon.mac")
	}
	if env.linux() && c.Inbound == nil {
		add(Info, "inbound.off", "Incoming connections are not filtered (inbound protection is off): services on this computer are reachable from every network.", "inbound")
	}

	names := make([]string, 0, len(c.Tunnels))
	for n := range c.Tunnels {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, name := range names {
		if env.OVPN == nil || !c.Tunnels[name].IsOpenVPN() {
			continue
		}
		if oc := env.OVPN(name); oc != nil {
			out = append(out, OpenVPN(name, oc)...)
		}
	}

	slices.SortStableFunc(out, func(a, b Finding) int { return cmp.Compare(rank(a.Level), rank(b.Level)) })
	return out
}

func rank(l string) int {
	switch l {
	case Bad:
		return 0
	case Warn:
		return 1
	}
	return 2
}

// weakCiphers are broken or obsolete block ciphers.
var weakCiphers = map[string]bool{
	"BF-CBC": true, "DES-CBC": true, "DES-EDE-CBC": true, "DES-EDE3-CBC": true, "RC2-CBC": true,
	"RC2-40-CBC": true, "RC2-64-CBC": true, "CAST5-CBC": true, "IDEA-CBC": true, "SEED-CBC": true,
}

// OpenVPN judges what a .ovpn file says about its own security (BSI
// NET.3.3 A4/A11: configure securely, use suitable protocols).
func OpenVPN(tunnel string, oc *ovpnconf.Config) []Finding {
	var out []Finding
	add := func(level, id, msg string) {
		out = append(out, Finding{ID: id, Level: level, Msg: msg, Vals: map[string]string{"tunnel": tunnel}})
	}
	weak, aead := false, false
	for _, c := range oc.Ciphers {
		if weakCiphers[c] {
			weak = true
		}
		if strings.Contains(c, "GCM") || strings.Contains(c, "CHACHA20-POLY1305") {
			aead = true
		}
	}
	switch {
	case weak:
		add(Bad, "ovpn.cipher", "Tunnel “{tunnel}”: the OpenVPN file allows a broken cipher (Blowfish, DES, RC2 …).")
	case len(oc.Ciphers) > 0 && !aead:
		add(Warn, "ovpn.cbc", "Tunnel “{tunnel}”: the OpenVPN file offers only CBC ciphers without authenticated encryption (AES-GCM or ChaCha20-Poly1305).")
	}
	if oc.Auth == "MD5" || oc.Auth == "SHA1" || oc.Auth == "MD4" {
		add(Warn, "ovpn.auth", "Tunnel “{tunnel}”: the OpenVPN file authenticates with a weak digest (MD5/SHA1).")
	}
	if oc.Compress {
		add(Warn, "ovpn.compress", "Tunnel “{tunnel}”: compression is on in the OpenVPN file (comp-lzo/compress). It enables attacks on the encrypted data (VORACLE).")
	}
	if !oc.TLSWrap {
		add(Warn, "ovpn.nowrap", "Tunnel “{tunnel}”: the OpenVPN file has no tls-crypt or tls-auth: the server answers anyone, port scans and attacks on the TLS handshake are not held back.")
	}
	if v := oc.TLSVersionMin; v == "1.0" || v == "1.1" {
		add(Warn, "ovpn.tls", "Tunnel “{tunnel}”: the OpenVPN file allows TLS older than 1.2.")
	}
	if !oc.RemoteCertTLS {
		add(Warn, "ovpn.nocerttype", "Tunnel “{tunnel}”: the OpenVPN file does not check that the server certificate is a server certificate (remote-cert-tls server): another user of the same provider could pose as the server.")
	}
	return out
}
