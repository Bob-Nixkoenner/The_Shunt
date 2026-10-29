package tunnel

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

func findPT(name string) string {
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	for _, d := range ptDirs {
		p := filepath.Join(d, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() && (runtime.GOOS == "windows" || st.Mode()&0o111 != 0) {
			return p
		}
	}
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	return ""
}

// torPlugins returns the ClientTransportPlugin lines the bridges need.
// lyrebird speaks obfs4, meek_lite, webtunnel and snowflake; without it,
// obfs4proxy (obfs4 only) and snowflake-client from the distribution do.
func torPlugins(bridges []string) ([]string, error) {
	need := map[string]bool{}
	for _, b := range bridges {
		if f := strings.Fields(b); len(f) > 0 && !strings.ContainsAny(f[0], ".:[") { // a transport name, not an address
			need[f[0]] = true
		}
	}
	if len(need) == 0 {
		return nil, nil
	}
	var names []string
	for n := range need {
		names = append(names, n)
	}
	sort.Strings(names)
	if p := findPT("lyrebird"); p != "" {
		return []string{"ClientTransportPlugin " + strings.Join(names, ",") + " exec " + p}, nil
	}
	var out, rest []string
	for _, n := range names {
		if n == "snowflake" {
			p := findPT("snowflake-client")
			if p == "" {
				return nil, errors.New("bridges use snowflake, but neither lyrebird nor snowflake-client is installed")
			}
			out = append(out, "ClientTransportPlugin snowflake exec "+p)
			continue
		}
		rest = append(rest, n)
	}
	if len(rest) > 0 {
		p := findPT("obfs4proxy")
		if p == "" || strings.Join(rest, ",") != "obfs4" {
			return nil, errors.New("bridges (" + strings.Join(rest, ", ") + ") need lyrebird, which is not installed")
		}
		out = append(out, "ClientTransportPlugin obfs4 exec "+p)
	}
	return out, nil
}

// trimTorLog drops tor's timestamp and level prefix.
func trimTorLog(l string) string {
	if i := strings.Index(l, "] "); i >= 0 {
		return l[i+2:]
	}
	return l
}
