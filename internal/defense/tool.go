package defense

import (
	"bufio"
	"bytes"
	"net/textproto"
	"strings"
)

// Tool marks: what program a decoy visitor uses, read from what it sends
// anyway (User-Agent, SSH client version, the fixed probes of nmap's service
// detection). A mark is reported as "tool=<name>" in the event detail and
// raises the heat (thermo.go). It is never a reason to block on its own: the
// marks are trivial to change, and curl or a headless browser are used by
// honest people as well.

// toolUA maps a lowercase User-Agent substring to a tool name. Order
// matters: the first hit wins (Playwright drives a headless Chromium).
var toolUA = []struct{ sub, name string }{
	{"nmap scripting engine", "nmap"},
	{"nmap", "nmap"},
	{"playwright", "playwright"},
	{"headlesschrome", "headless_chromium"},
	{"puppeteer", "puppeteer"},
	{"curl/", "curl"},
	{"wget/", "wget"},
	{"python-requests/", "python_requests"},
	{"python-urllib", "python_urllib"},
	{"python-httpx/", "python_httpx"},
	{"aiohttp/", "python_aiohttp"},
	{"go-http-client/", "go_http"},
	{"masscan", "masscan"},
	{"zgrab", "zgrab"},
	{"nikto", "nikto"},
	{"sqlmap", "sqlmap"},
	{"nuclei", "nuclei"},
	{"gobuster", "gobuster"},
	{"ffuf", "ffuf"},
}

// ToolFromUA names the tool of a User-Agent ("" = none known).
func ToolFromUA(ua string) string {
	l := strings.ToLower(ua)
	for _, t := range toolUA {
		if strings.Contains(l, t.sub) {
			return t.name
		}
	}
	return ""
}

// Fixed probes of nmap's service detection (nmap-service-probes): the 404
// probe for web servers and the SIP OPTIONS probe.
var nmapProbes = [][]byte{
	[]byte("/nice%20ports%2C/Tri%6Eity.txt%2ebak"),
	[]byte("/nice ports,/Trinity.txt.bak"),
	[]byte("OPTIONS sip:nm SIP/2.0"),
}

// toolFromRequest names the tool of an HTTP request: nmap probe paths first,
// then the User-Agent.
func toolFromRequest(uri, ua string) string {
	for _, p := range nmapProbes[:2] {
		if strings.Contains(uri, string(p)) {
			return "nmap"
		}
	}
	return ToolFromUA(ua)
}

// toolFromPayload looks at the first bytes a client sent to a plain decoy
// port: an nmap probe, or an HTTP request with a known User-Agent.
func toolFromPayload(b []byte) string {
	for _, p := range nmapProbes {
		if bytes.Contains(b, p) {
			return "nmap"
		}
	}
	line, rest, ok := bytes.Cut(b, []byte("\n"))
	if !ok || !bytes.Contains(line, []byte(" HTTP/1.")) {
		return ""
	}
	h, _ := textproto.NewReader(bufio.NewReader(bytes.NewReader(rest))).ReadMIMEHeader()
	return ToolFromUA(h.Get("User-Agent"))
}

// ToolFromSSHClient names the tool of an SSH client version string. Real
// OpenSSH, PuTTY and the like give "".
func ToolFromSSHClient(v string) string {
	l := strings.ToLower(v)
	switch {
	case strings.Contains(l, "nmap"):
		return "nmap"
	case strings.Contains(l, "paramiko"):
		return "python_paramiko"
	case strings.Contains(l, "asyncssh"):
		return "python_asyncssh"
	case strings.Contains(l, "libssh"): // hydra, medusa, many scanners
		return "libssh"
	case strings.HasPrefix(l, "ssh-2.0-go"):
		return "go_ssh"
	case strings.Contains(l, "zgrab"):
		return "zgrab"
	}
	return ""
}

// toolDetail is the detail suffix for a tool ("" when none).
func toolDetail(tool string) string {
	if tool == "" {
		return ""
	}
	return " tool=" + tool
}

// hasTool reports whether an event detail carries a tool mark.
func hasTool(detail string) bool {
	return strings.HasPrefix(detail, "tool=") || strings.Contains(detail, " tool=")
}
