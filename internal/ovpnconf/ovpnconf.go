// Package ovpnconf checks OpenVPN client configs (.ovpn) before shuntd hands
// them to the openvpn binary, which runs as root inside shuntd's service.
//
// A .ovpn file is code as much as config: "up", "plugin" and friends run
// programs, "log"/"status"/"writepid" write files anywhere, "user" changes
// privileges. Shunt refuses those. Routes and DNS settings in the file are
// harmless: shuntd starts openvpn with --route-noexec and does routing and
// DNS itself.
package ovpnconf

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Config is what Shunt needs to know about a .ovpn file.
type Config struct {
	// Remotes are the "remote" lines (host [port] [proto]), for display.
	Remotes []string
	// NeedsAuth: the server wants a username and password
	// (auth-user-pass without an inline block).
	NeedsAuth bool
	// AuthFile is the file named by "auth-user-pass <file>", if any.
	AuthFile string
	// Files referenced by path (ca, cert, key, …), resolved against the
	// config's directory.
	Files []string
}

// forbidden directives, with the reason shown to the user.
var forbidden = map[string]string{
	"up": "runs a program", "down": "runs a program", "route-up": "runs a program",
	"route-pre-down": "runs a program", "ipchange": "runs a program",
	"client-connect": "runs a program", "client-disconnect": "runs a program",
	"learn-address": "runs a program", "auth-user-pass-verify": "runs a program",
	"tls-verify": "runs a program", "tls-crypt-v2-verify": "runs a program",
	"plugin": "loads a library", "iproute": "runs a program", "script-security": "enables scripts",
	"management": "opens a control port", "management-external-key": "needs a management client",
	"management-external-cert": "needs a management client", "management-query-passwords": "needs a management client",
	"management-hold": "needs a management client", "management-client": "needs a management client",
	"daemon": "Shunt runs openvpn itself", "log": "writes a file", "log-append": "writes a file",
	"status": "writes a file", "writepid": "writes a file", "cd": "changes directory",
	"chroot": "changes root", "config": "includes another file", "user": "drops privileges (breaks reconnects)",
	"group": "drops privileges (breaks reconnects)", "tmp-dir": "writes files", "askpass": "prompts on a terminal",
	"server": "server mode", "mode": "server mode", "tls-server": "server mode",
	"client-config-dir": "server mode", "ifconfig-pool": "server mode",
	"echo": "talks to a management client", "syslog": "Shunt collects the log",
	"setcon": "SELinux context switch",
}

// fileArgs take a path (or an inline block) as first argument.
var fileArgs = map[string]bool{
	"ca": true, "cert": true, "key": true, "tls-auth": true, "tls-crypt": true,
	"tls-crypt-v2": true, "pkcs12": true, "crl-verify": true, "secret": true,
	"extra-certs": true, "dh": true, "http-proxy-user-pass": true,
}

// ParseFile reads and checks a .ovpn file. Relative file references are
// resolved against its directory.
func ParseFile(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(string(b), filepath.Dir(path))
}

// Parse checks config text. dir resolves relative file references; ""
// means none are allowed (import of a single file).
func Parse(s, dir string) (*Config, error) {
	c := &Config{}
	inline := map[string]bool{}
	var problems []string
	sc := bufio.NewScanner(strings.NewReader(s))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	block := ""
	line := 0
	var authArg string
	sawAuth := false
	for sc.Scan() {
		line++
		l := strings.TrimSpace(sc.Text())
		if block != "" {
			if strings.EqualFold(l, "</"+block+">") {
				inline[block] = true
				block = ""
			}
			continue
		}
		if l == "" || l[0] == '#' || l[0] == ';' {
			continue
		}
		if strings.HasPrefix(l, "<") && strings.HasSuffix(l, ">") && !strings.HasPrefix(l, "</") {
			block = strings.ToLower(strings.Trim(l, "<>"))
			if _, bad := forbidden[block]; bad {
				problems = append(problems, fmt.Sprintf("line %d: <%s> block (%s)", line, block, forbidden[block]))
			}
			continue
		}
		f := fields(l)
		if len(f) == 0 {
			continue
		}
		name := strings.ToLower(strings.TrimPrefix(f[0], "--"))
		if why, bad := forbidden[name]; bad {
			problems = append(problems, fmt.Sprintf("line %d: %q (%s)", line, name, why))
			continue
		}
		switch {
		case name == "remote" && len(f) > 1:
			c.Remotes = append(c.Remotes, strings.Join(f[1:], " "))
		case name == "auth-user-pass":
			sawAuth = true
			if len(f) > 1 {
				authArg = f[1]
			}
		case fileArgs[name] && len(f) > 1 && f[1] != "[inline]":
			c.Files = append(c.Files, f[1])
		}
	}
	if block != "" {
		problems = append(problems, fmt.Sprintf("<%s> block is not closed", block))
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(problems) > 0 {
		return nil, fmt.Errorf("not allowed in a Shunt OpenVPN config: %s", strings.Join(problems, "; "))
	}
	if len(c.Remotes) == 0 {
		return nil, fmt.Errorf("no \"remote\" line: is this an OpenVPN client config?")
	}
	if sawAuth && !inline["auth-user-pass"] {
		if authArg != "" {
			c.AuthFile = authArg
		} else {
			c.NeedsAuth = true
		}
	}
	if c.AuthFile != "" {
		c.Files = append(c.Files, c.AuthFile)
	}
	for i, p := range c.Files {
		if dir == "" {
			return nil, fmt.Errorf("%q refers to a separate file; use a config with the certificates inline (<ca>…</ca>), as most providers offer", p)
		}
		if !filepath.IsAbs(p) {
			p = filepath.Join(dir, p)
		}
		if _, err := os.Stat(p); err != nil {
			return nil, fmt.Errorf("file referenced in the config: %w", err)
		}
		c.Files[i] = p
	}
	sort.Strings(c.Files)
	return c, nil
}

// fields splits a config line like openvpn does: whitespace separated,
// double or single quotes group, a # or ; starts a comment.
func fields(l string) []string {
	var out []string
	var cur strings.Builder
	in := false
	quote := byte(0)
	for i := 0; i < len(l); i++ {
		ch := l[i]
		switch {
		case quote != 0:
			if ch == quote {
				quote = 0
			} else {
				cur.WriteByte(ch)
			}
		case ch == '"' || ch == '\'':
			quote, in = ch, true
		case ch == ' ' || ch == '\t':
			if in {
				out = append(out, cur.String())
				cur.Reset()
				in = false
			}
		case (ch == '#' || ch == ';') && !in:
			i = len(l)
		default:
			cur.WriteByte(ch)
			in = true
		}
	}
	if in {
		out = append(out, cur.String())
	}
	return out
}
