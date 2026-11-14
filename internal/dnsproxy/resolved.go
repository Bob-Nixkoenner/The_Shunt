package dnsproxy

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// resolvedConfDirs are systemd-resolved's drop-in folders, lowest priority
// first (a later file of the same name wins, all are read in name order).
var resolvedConfDirs = []string{"/usr/lib/systemd/resolved.conf.d", "/run/systemd/resolved.conf.d", "/etc/systemd/resolved.conf.d"}

var resolvedConf = "/etc/systemd/resolved.conf"

// ResolvedProtections lists what systemd-resolved is set to protect its
// queries with (DNSOverTLS, DNSSEC), from resolved.conf and its drop-ins.
// dns.direct = "system" bypasses them (report L-13): SystemUpstreams asks
// resolved's upstreams itself, in plain UDP, because sending to the stub on
// loopback would loop back into the proxy. Empty: nothing set (or resolved
// not configured), so nothing is lost.
func ResolvedProtections() []string {
	files := []string{resolvedConf}
	byName := map[string]string{}
	for _, d := range resolvedConfDirs {
		ms, _ := filepath.Glob(filepath.Join(d, "*.conf"))
		for _, m := range ms {
			byName[filepath.Base(m)] = m
		}
	}
	names := make([]string, 0, len(byName))
	for n := range byName {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		files = append(files, byName[n])
	}
	vals := map[string]string{}
	for _, f := range files {
		readResolvedConf(f, vals)
	}
	var out []string
	on := func(v string, ok ...string) bool {
		for _, o := range ok {
			if strings.EqualFold(v, o) {
				return true
			}
		}
		return false
	}
	if v := vals["DNSOverTLS"]; on(v, "yes", "true", "1", "opportunistic") {
		out = append(out, "DNSOverTLS="+v)
	}
	if v := vals["DNSSEC"]; on(v, "yes", "true", "1", "allow-downgrade") {
		out = append(out, "DNSSEC="+v)
	}
	return out
}

// readResolvedConf reads the [Resolve] keys of one file into vals (later
// files overwrite earlier ones, as resolved does).
func readResolvedConf(path string, vals map[string]string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	in := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || l[0] == '#' || l[0] == ';' {
			continue
		}
		if strings.HasPrefix(l, "[") {
			in = l == "[Resolve]"
			continue
		}
		if k, v, ok := strings.Cut(l, "="); ok && in {
			vals[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
}
