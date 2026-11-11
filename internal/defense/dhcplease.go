package defense

import (
	"bufio"
	"bytes"
	"context"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// LeaseServers returns the DHCP server addresses of this client's current
// lease on the interface, as far as readable without root: NetworkManager
// (nmcli), systemd-networkd lease files, dhclient lease files. It never
// fails; it returns nil when nothing is readable.
func LeaseServers(iface string, ifindex int) []netip.Addr {
	var out []netip.Addr
	add := func(a []netip.Addr) { out = append(out, a...) }
	if p, err := exec.LookPath("nmcli"); err == nil && iface != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		b, _ := exec.CommandContext(ctx, p, "-g", "DHCP4", "device", "show", iface).Output()
		cancel()
		add(parseNMCLIDHCP(string(b)))
	}
	if len(out) == 0 && ifindex > 0 {
		if b, err := os.ReadFile("/run/systemd/netif/leases/" + strconv.Itoa(ifindex)); err == nil {
			add(parseNetworkdLease(string(b)))
		}
	}
	if len(out) == 0 && iface != "" {
		for _, pat := range []string{"/var/lib/dhcp/dhclient*" + iface + "*.leases", "/var/lib/dhcp/dhclient.leases",
			"/var/lib/NetworkManager/*" + iface + "*.lease", "/var/lib/dhclient/dhclient*" + iface + "*.leases"} {
			m, _ := filepath.Glob(pat)
			for _, f := range m {
				if b, err := os.ReadFile(f); err == nil {
					add(parseDhclientLease(string(b), iface))
				}
			}
		}
	}
	return out
}

// parseNMCLIDHCP reads "DHCP4.OPTION[n]:dhcp_server_identifier = x" lines.
func parseNMCLIDHCP(s string) []netip.Addr {
	var out []netip.Addr
	for _, l := range strings.Split(s, "\n") {
		if i := strings.Index(l, "dhcp_server_identifier"); i >= 0 {
			if j := strings.Index(l[i:], "="); j >= 0 {
				if a, err := netip.ParseAddr(strings.TrimSpace(l[i+j+1:])); err == nil {
					out = append(out, a)
				}
			}
		}
	}
	return out
}

// parseNetworkdLease reads SERVER_ADDRESS=x.
func parseNetworkdLease(s string) []netip.Addr {
	var out []netip.Addr
	for _, l := range strings.Split(s, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "SERVER_ADDRESS="); ok {
			if a, err := netip.ParseAddr(strings.TrimSpace(v)); err == nil {
				out = append(out, a)
			}
		}
	}
	return out
}

// parseDhclientLease returns the server of the last lease block for iface
// (any block when the file names no interface).
func parseDhclientLease(s, iface string) []netip.Addr {
	var last netip.Addr
	var cur netip.Addr
	match := true
	sc := bufio.NewScanner(bytes.NewReader([]byte(s)))
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(l, "lease {"):
			cur, match = netip.Addr{}, true
		case strings.HasPrefix(l, "interface "):
			match = strings.Trim(strings.TrimPrefix(l, "interface "), `";`) == iface
		case strings.HasPrefix(l, "option dhcp-server-identifier "):
			a, err := netip.ParseAddr(strings.Trim(strings.TrimPrefix(l, "option dhcp-server-identifier "), "; "))
			if err == nil {
				cur = a
			}
		case l == "}":
			if match && cur.IsValid() {
				last = cur
			}
		}
	}
	// a bare NetworkManager lease file has no braces
	if !last.IsValid() && cur.IsValid() && match {
		last = cur
	}
	if last.IsValid() {
		return []netip.Addr{last}
	}
	return nil
}
